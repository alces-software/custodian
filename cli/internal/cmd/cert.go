// =============================================================================
// Copyright (C) 2026 Alces Software Ltd.
//
// This file is part of Custodian CLI.
//
// This program and the accompanying materials are made available under
// the terms of the Eclipse Public License 2.0 which is available at
// <https://www.eclipse.org/legal/epl-2.0>, or alternative license
// terms made available by Alces Software Ltd - please direct inquiries
// about licensing to licensing@alces-flight.com.
//
// Custodian CLI is distributed in the hope that it will be useful, but
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR
// IMPLIED INCLUDING, WITHOUT LIMITATION, ANY WARRANTIES OR CONDITIONS
// OF TITLE, NON-INFRINGEMENT, MERCHANTABILITY OR FITNESS FOR A
// PARTICULAR PURPOSE. See the Eclipse Public License 2.0 for more
// details.
//
// You should have received a copy of the Eclipse Public License 2.0
// along with Custodian CLI. If not, see:
//
//  https://opensource.org/licenses/EPL-2.0
//
// For more information on Custodian CLI, please visit:
// https://github.com/alces-software/custodian-cli
// ==============================================================================

package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"alces/custodian-cli/internal/client"
)

func newCertCmd(opts *rootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cert",
		Short: "Manage certificates",
	}
	cmd.AddCommand(newCertListCmd(opts))
	cmd.AddCommand(newCertGetCmd(opts))
	cmd.AddCommand(newCertIssueCmd(opts))
	cmd.AddCommand(newCertRenewCmd(opts))
	cmd.AddCommand(newCertRenewDueCmd(opts))
	cmd.AddCommand(newCertDeleteCmd(opts))
	cmd.AddCommand(newCertBundleCmd(opts))
	return cmd
}

func newCertListCmd(opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List certificates",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := opts.authClient()
			if err != nil {
				return err
			}
			list, err := c.ListCertificates(cmd.Context())
			if err != nil {
				return err
			}
			return opts.printer().PrintCertList(list.Certificates)
		},
	}
}

func newCertGetCmd(opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "get <id>",
		Short: "Get certificate metadata",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := opts.authClient()
			if err != nil {
				return err
			}
			cert, err := c.GetCertificate(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return opts.printer().PrintCert(cert)
		},
	}
}

func newCertIssueCmd(opts *rootOptions) *cobra.Command {
	var force bool
	var accessKey string
	var accessKeyID string
	cmd := &cobra.Command{
		Use:   "issue <common_name> [san...]",
		Short: "Issue a certificate (or return still-valid cert)",
		Long: `Issue a certificate for the given common name (and optional SANs).

When authenticating as an access key, the cert is bound to that key.
When authenticating as admin, pass --access-key or --access-key-id of a
registered key to issue on its behalf.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if accessKey != "" && accessKeyID != "" {
				return &ExitError{Code: exitUsage, Msg: "--access-key and --access-key-id are mutually exclusive"}
			}
			c, err := opts.authClient()
			if err != nil {
				return err
			}
			var sans []string
			if len(args) > 1 {
				sans = args[1:]
			}
			cert, err := c.Issue(cmd.Context(), client.IssueRequest{
				CommonName:  args[0],
				SANs:        sans,
				Force:       force,
				AccessKey:   accessKey,
				AccessKeyID: accessKeyID,
			})
			if err != nil {
				return err
			}
			return opts.printer().PrintCert(cert)
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Force re-issue even if a valid cert exists")
	cmd.Flags().StringVar(&accessKey, "access-key", "", "Registered access key secret (admin issue-on-behalf)")
	cmd.Flags().StringVar(&accessKeyID, "access-key-id", "", "Registered access key id (admin issue-on-behalf)")
	return cmd
}

func newCertRenewCmd(opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "renew <id>",
		Short: "Force-renew one certificate",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := opts.authClient()
			if err != nil {
				return err
			}
			cert, err := c.RenewOne(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return opts.printer().PrintCert(cert)
		},
	}
}

func newCertRenewDueCmd(opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "renew-due",
		Short: "Renew all certificates due for renewal (admin)",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := opts.authClient()
			if err != nil {
				return err
			}
			res, err := c.RenewDue(cmd.Context())
			if err != nil {
				return err
			}
			if err := opts.printer().PrintRenewResult(res); err != nil {
				return err
			}
			if len(res.Failed) > 0 {
				return &ExitError{Code: exitFail, Msg: fmt.Sprintf("%d renewal(s) failed", len(res.Failed))}
			}
			return nil
		},
	}
}

func newCertDeleteCmd(opts *rootOptions) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "delete <id>",
		Short: "Soft-delete a certificate",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !yes {
				fi, _ := os.Stdin.Stat()
				isTTY := fi != nil && (fi.Mode()&os.ModeCharDevice) != 0
				if !isTTY {
					return &ExitError{Code: exitUsage, Msg: "refusing to delete without --yes in non-interactive mode"}
				}
				fmt.Fprintf(os.Stderr, "Delete certificate %s? [y/N] ", args[0])
				var answer string
				_, _ = fmt.Scanln(&answer)
				if answer != "y" && answer != "Y" && answer != "yes" {
					return &ExitError{Code: exitUsage, Msg: "delete cancelled"}
				}
			}
			c, err := opts.authClient()
			if err != nil {
				return err
			}
			if err := c.DeleteCertificate(cmd.Context(), args[0]); err != nil {
				return err
			}
			p := opts.printer()
			if opts.json {
				return p.PrintJSON(map[string]string{"deleted": args[0]})
			}
			fmt.Fprintf(p.Out, "deleted %s\n", args[0])
			return nil
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip confirmation")
	return cmd
}

func newCertBundleCmd(opts *rootOptions) *cobra.Command {
	var outDir string
	var format string
	cmd := &cobra.Command{
		Use:   "bundle <id>",
		Short: "Download certificate bundle (private key + PEMs)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if outDir != "" && format == "pem" {
				return &ExitError{Code: exitUsage, Msg: "--out and --format pem are mutually exclusive"}
			}
			c, err := opts.authClient()
			if err != nil {
				return err
			}
			id := args[0]
			ctx := cmd.Context()
			p := opts.printer()

			if format == "pem" {
				raw, err := c.GetBundlePEM(ctx, id)
				if err != nil {
					return err
				}
				_, err = p.Out.Write(raw)
				return err
			}

			b, err := c.GetBundle(ctx, id)
			if err != nil {
				return err
			}

			if outDir != "" {
				if err := os.MkdirAll(outDir, 0o755); err != nil {
					return err
				}
				type fileSpec struct {
					name string
					data string
					mode os.FileMode
				}
				files := []fileSpec{
					{"privkey.pem", b.PrivateKeyPEM, 0o600},
					{"fullchain.pem", b.FullchainPEM, 0o644},
					{"cert.pem", b.CertificatePEM, 0o644},
				}
				if b.ChainPEM != "" {
					files = append(files, fileSpec{"chain.pem", b.ChainPEM, 0o644})
				}
				for _, f := range files {
					path := filepath.Join(outDir, f.name)
					if err := os.WriteFile(path, []byte(f.data), f.mode); err != nil {
						return err
					}
				}
				if opts.json {
					return p.PrintJSON(map[string]string{"id": id, "out": outDir})
				}
				fmt.Fprintf(p.Out, "wrote bundle for %s (%s) to %s\n", b.ID, b.CommonName, outDir)
				return nil
			}

			// Default: no secrets on stdout
			if opts.json {
				return p.PrintJSON(b)
			}
			fmt.Fprintf(p.Out, "ID:          %s\n", b.ID)
			fmt.Fprintf(p.Out, "Common Name: %s\n", b.CommonName)
			fmt.Fprintf(p.Out, "(use --json for PEMs, --out DIR to write files, or --format pem)\n")
			return nil
		},
	}
	cmd.Flags().StringVar(&outDir, "out", "", "Directory to write PEM files")
	cmd.Flags().StringVar(&format, "format", "", `Use "pem" for combined key+fullchain on stdout`)
	return cmd
}
