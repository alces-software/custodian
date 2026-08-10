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
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"alces/custodian-cli/internal/client"
	"alces/custodian-cli/internal/config"
	"alces/custodian-cli/internal/output"
)

const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2
)

type rootOptions struct {
	url     string
	authKey string
	profile string
	config  string
	json    bool
	timeout time.Duration
}

// ExitError carries a process exit code.
type ExitError struct {
	Code int
	Msg  string
}

func (e *ExitError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return fmt.Sprintf("exit %d", e.Code)
}

// Execute runs the root command and exits the process on error.
func Execute() {
	if err := NewRoot().Execute(); err != nil {
		code := exitFail
		msg := err.Error()
		var ee *ExitError
		if errors.As(err, &ee) {
			code = ee.Code
			if ee.Msg != "" {
				msg = ee.Msg
			}
		}
		fmt.Fprintf(os.Stderr, "error: %s\n", msg)
		os.Exit(code)
	}
}

// NewRoot builds the root cobra command.
func NewRoot() *cobra.Command {
	opts := &rootOptions{}

	root := &cobra.Command{
		Use:           "custodian",
		Short:         "CLI for the Custodian certificate API",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().StringVar(&opts.url, "url", "", "Custodian base URL (or CUSTODIAN_URL)")
	root.PersistentFlags().StringVar(&opts.authKey, "auth-key", "", "Bearer token (or CUSTODIAN_AUTH_KEY)")
	root.PersistentFlags().StringVar(&opts.profile, "profile", "", "Config profile name")
	root.PersistentFlags().StringVar(&opts.config, "config", "", "Config file path (default: XDG ~/.config/custodian/config.yaml, else <binary>/../etc/config.yaml)")
	root.PersistentFlags().BoolVar(&opts.json, "json", false, "JSON output")
	root.PersistentFlags().DurationVar(&opts.timeout, "timeout", 120*time.Second, "HTTP client timeout")

	root.AddCommand(newHealthCmd(opts))
	root.AddCommand(newAccessKeyCmd(opts))
	root.AddCommand(newCertCmd(opts))

	return root
}

func (o *rootOptions) resolve() (config.Resolved, error) {
	return config.Resolve(config.Options{
		ConfigPath: o.config, // empty → FindConfigPath (XDG, else binary ../etc)
		Profile:    o.profile,
		URL:        o.url,
		AuthKey:    o.authKey,
	})
}

func (o *rootOptions) authClient() (*client.Client, error) {
	res, err := o.resolve()
	if err != nil {
		return nil, err
	}
	if err := res.RequireAuth(); err != nil {
		return nil, &ExitError{Code: exitUsage, Msg: err.Error()}
	}
	return client.New(res.URL, res.AuthKey, o.timeout), nil
}

func (o *rootOptions) urlClient() (*client.Client, error) {
	res, err := o.resolve()
	if err != nil {
		return nil, err
	}
	if err := res.RequireURL(); err != nil {
		return nil, &ExitError{Code: exitUsage, Msg: err.Error()}
	}
	return client.New(res.URL, res.AuthKey, o.timeout), nil
}

func (o *rootOptions) printer() *output.Printer {
	return output.New(o.json)
}
