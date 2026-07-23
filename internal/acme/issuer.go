package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/gcloud"
	"github.com/go-acme/lego/v4/registration"

	sealer "github.com/markt/custodian/internal/crypto"
	"github.com/markt/custodian/internal/store"
)

// Config for the ACME issuer.
type Config struct {
	Email                 string
	DirectoryURL          string
	GCPProject            string
	CloudDNSZone          string
	GCPServiceAccountJSON string
	DNSPropagationTimeout time.Duration
}

// Result is the outcome of an issue/renew operation.
type Result struct {
	PrivateKeyPEM  string
	CertificatePEM string
	ChainPEM       string
	Issuer         string
	Serial         string
	NotBefore      time.Time
	NotAfter       time.Time
}

// Issuer obtains certificates via Let's Encrypt DNS-01 (Cloud DNS).
type Issuer struct {
	cfg   Config
	store *store.Store
	box   *sealer.Box
	mu    sync.Mutex // serialize ACME operations process-wide
}

// NewIssuer constructs an Issuer.
func NewIssuer(cfg Config, st *store.Store, box *sealer.Box) *Issuer {
	return &Issuer{cfg: cfg, store: st, box: box}
}

// user implements registration.User.
type user struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *user) GetEmail() string                        { return u.Email }
func (u *user) GetRegistration() *registration.Resource { return u.Registration }
func (u *user) GetPrivateKey() crypto.PrivateKey        { return u.key }

// Obtain issues a new certificate for the given names (CN first).
// zone is the Cloud DNS managed zone id/name for this order (required for multi-zone catalogs).
func (i *Issuer) Obtain(ctx context.Context, names []string, zone string) (*Result, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("no names")
	}
	i.mu.Lock()
	defer i.mu.Unlock()

	client, err := i.client(ctx, zone)
	if err != nil {
		return nil, err
	}

	request := certificate.ObtainRequest{
		Domains: names,
		Bundle:  true,
	}
	// lego doesn't take context on Obtain in all versions; check cancel before/after
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	certs, err := client.Certificate.Obtain(request)
	if err != nil {
		return nil, fmt.Errorf("acme obtain: %w", err)
	}
	return parseCertificateResource(certs)
}

func (i *Issuer) client(ctx context.Context, zone string) (*lego.Client, error) {
	if err := i.prepareGCPEnv(zone); err != nil {
		return nil, err
	}

	u, err := i.loadOrCreateUser(ctx)
	if err != nil {
		return nil, err
	}

	config := lego.NewConfig(u)
	config.CADirURL = i.cfg.DirectoryURL
	config.Certificate.KeyType = certcrypto.EC256

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("lego client: %w", err)
	}

	provider, err := gcloud.NewDNSProvider()
	if err != nil {
		return nil, fmt.Errorf("gcloud dns provider: %w", err)
	}

	err = client.Challenge.SetDNS01Provider(provider,
		dns01.AddRecursiveNameservers([]string{"8.8.8.8:53", "1.1.1.1:53"}),
	)
	if err != nil {
		return nil, fmt.Errorf("set dns01: %w", err)
	}

	// Prefer resolving an existing account by key (survives partial URI storage).
	if u.Registration == nil || u.Registration.URI == "" {
		reg, err := client.Registration.ResolveAccountByKey()
		if err != nil {
			reg, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
			if err != nil {
				return nil, fmt.Errorf("acme register: %w", err)
			}
		}
		u.Registration = reg
		if err := i.persistUser(ctx, u); err != nil {
			return nil, err
		}
	}

	return client, nil
}

func (i *Issuer) prepareGCPEnv(zone string) error {
	if i.cfg.GCPServiceAccountJSON != "" {
		// lego accepts the raw JSON in GCE_SERVICE_ACCOUNT
		_ = os.Setenv("GCE_SERVICE_ACCOUNT", i.cfg.GCPServiceAccountJSON)
		// Also materialize ADC path if not already set (other Google clients).
		if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") == "" {
			f, err := os.CreateTemp("", "gcp-sa-*.json")
			if err != nil {
				return err
			}
			if _, err := f.WriteString(i.cfg.GCPServiceAccountJSON); err != nil {
				_ = f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
			_ = os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", f.Name())
		}
	}
	if i.cfg.GCPProject != "" {
		_ = os.Setenv("GCE_PROJECT", i.cfg.GCPProject)
	}
	// Pin zone for this obtain. Prefer explicit zone arg; fall back to static config.
	// Always set or clear under the ACME mutex so a prior obtain cannot leak zone.
	z := strings.TrimSpace(zone)
	if z == "" {
		z = strings.TrimSpace(i.cfg.CloudDNSZone)
	}
	if z != "" {
		_ = os.Setenv("GCE_ZONE_ID", z)
	} else {
		_ = os.Unsetenv("GCE_ZONE_ID")
	}
	if i.cfg.DNSPropagationTimeout > 0 {
		_ = os.Setenv("GCE_POLLING_INTERVAL", "5")
		sec := int(i.cfg.DNSPropagationTimeout.Seconds())
		if sec < 30 {
			sec = 30
		}
		_ = os.Setenv("GCE_PROPAGATION_TIMEOUT", fmt.Sprintf("%d", sec))
	}
	return nil
}

func (i *Issuer) loadOrCreateUser(ctx context.Context) (*user, error) {
	acc, err := i.store.GetLEAccountByDirectory(ctx, i.cfg.DirectoryURL)
	if err == store.ErrNotFound {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		u := &user{Email: i.cfg.Email, key: key}
		if err := i.persistUser(ctx, u); err != nil {
			return nil, err
		}
		return u, nil
	}
	if err != nil {
		return nil, err
	}
	raw, err := i.box.Open(acc.PrivateKeyEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt le account key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("invalid le account key pem")
	}
	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		// try PKCS8
		k, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parse le account key: %w", err)
		}
		var ok bool
		priv, ok = k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("le account key is not ECDSA")
		}
	}
	u := &user{
		Email: acc.Email,
		key:   priv,
	}
	if acc.RegistrationURI != "" {
		u.Registration = &registration.Resource{URI: acc.RegistrationURI}
	}
	return u, nil
}

func (i *Issuer) persistUser(ctx context.Context, u *user) error {
	der, err := x509.MarshalECPrivateKey(u.key.(*ecdsa.PrivateKey))
	if err != nil {
		return err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	enc, err := i.box.Seal(pemBytes)
	if err != nil {
		return err
	}
	uri := ""
	if u.Registration != nil {
		uri = u.Registration.URI
	}
	_, err = i.store.UpsertLEAccount(ctx, u.Email, enc, uri, i.cfg.DirectoryURL)
	return err
}

func parseCertificateResource(res *certificate.Resource) (*Result, error) {
	if res == nil {
		return nil, fmt.Errorf("empty certificate resource")
	}
	// Certificate is fullchain when Bundle=true; IssuerCertificate is intermediate(s).
	certPEM := string(res.Certificate)
	chainPEM := string(res.IssuerCertificate)
	keyPEM := string(res.PrivateKey)

	// Parse leaf for metadata
	block, _ := pem.Decode(res.Certificate)
	if block == nil {
		return nil, fmt.Errorf("decode certificate pem")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	// If fullchain includes intermediates, split leaf vs chain for storage clarity
	rest := res.Certificate[len(pem.EncodeToMemory(block)):]
	if len(rest) > 0 && chainPEM == "" {
		chainPEM = string(rest)
		certPEM = string(pem.EncodeToMemory(block))
	} else if chainPEM != "" {
		// keep leaf-only cert if we can
		certPEM = string(pem.EncodeToMemory(block))
	}

	return &Result{
		PrivateKeyPEM:  keyPEM,
		CertificatePEM: certPEM,
		ChainPEM:       strings.TrimSpace(chainPEM) + "\n",
		Issuer:         leaf.Issuer.String(),
		Serial:         leaf.SerialNumber.Text(16),
		NotBefore:      leaf.NotBefore.UTC(),
		NotAfter:       leaf.NotAfter.UTC(),
	}, nil
}
