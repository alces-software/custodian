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
	"crypto/rand"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"alces/custodian-cli/internal/client"
)

func newAccessKeyCmd(opts *rootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "access-key",
		Aliases: []string{"key"},
		Short:   "Manage client access keys",
	}
	cmd.AddCommand(newAccessKeyRegisterCmd(opts))
	cmd.AddCommand(newAccessKeyListCmd(opts))
	cmd.AddCommand(newAccessKeyGetCmd(opts))
	cmd.AddCommand(newAccessKeyUpdateCmd(opts))
	cmd.AddCommand(newAccessKeyRevokeCmd(opts))
	return cmd
}

func newAccessKeyRegisterCmd(opts *rootOptions) *cobra.Command {
	var (
		key   string
		desc  string
		brief bool
	)
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register a client access key (admin or registrar)",
		Long: `Register a client-held access key. The raw secret is hashed server-side
and never returned again — save it when generated.

Requires a registrar or admin bearer token (--auth-key / CUSTODIAN_AUTH_KEY).

With --brief, print only the access key secret on stdout (script-friendly):

  KEY=$(custodian access-key register -d "myapp" --brief)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			generated := false
			if key == "" {
				var err error
				key, err = generateAccessKey()
				if err != nil {
					return err
				}
				generated = true
			}
			c, err := opts.authClient()
			if err != nil {
				return err
			}
			ak, err := c.RegisterAccessKey(cmd.Context(), client.RegisterAccessKeyRequest{
				AccessKey:   key,
				Description: desc,
			})
			if err != nil {
				return err
			}
			if brief {
				fmt.Fprintln(opts.printer().Out, key)
				return nil
			}
			if generated {
				// Surface the secret once when we minted it.
				fmt.Fprintf(os.Stderr, "generated access key (save it; not shown again):\n%s\n", key)
			}
			return opts.printer().PrintAccessKey(ak)
		},
	}
	cmd.Flags().StringVar(&key, "key", "", "Access key secret to register (default: generate a UUID)")
	cmd.Flags().StringVarP(&desc, "description", "d", "", "Human-readable description")
	cmd.Flags().BoolVar(&brief, "brief", false, "Print only the access key secret on stdout")
	return cmd
}

func newAccessKeyListCmd(opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List access keys (admin)",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := opts.authClient()
			if err != nil {
				return err
			}
			list, err := c.ListAccessKeys(cmd.Context())
			if err != nil {
				return err
			}
			return opts.printer().PrintAccessKeyList(list.AccessKeys)
		},
	}
}

func newAccessKeyGetCmd(opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "get <id>",
		Short: "Get access key metadata (admin)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := opts.authClient()
			if err != nil {
				return err
			}
			ak, err := c.GetAccessKey(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return opts.printer().PrintAccessKey(ak)
		},
	}
}

func newAccessKeyUpdateCmd(opts *rootOptions) *cobra.Command {
	var desc string
	cmd := &cobra.Command{
		Use:   "update <id>",
		Short: "Update access key description (admin)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("description") {
				return &ExitError{Code: exitUsage, Msg: "--description is required"}
			}
			c, err := opts.authClient()
			if err != nil {
				return err
			}
			ak, err := c.UpdateAccessKeyDescription(cmd.Context(), args[0], desc)
			if err != nil {
				return err
			}
			return opts.printer().PrintAccessKey(ak)
		},
	}
	cmd.Flags().StringVarP(&desc, "description", "d", "", "New description (use empty string to clear)")
	return cmd
}

func newAccessKeyRevokeCmd(opts *rootOptions) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "revoke <id>",
		Short: "Soft-revoke an access key (admin)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !yes {
				fi, _ := os.Stdin.Stat()
				isTTY := fi != nil && (fi.Mode()&os.ModeCharDevice) != 0
				if !isTTY {
					return &ExitError{Code: exitUsage, Msg: "refusing to revoke without --yes in non-interactive mode"}
				}
				fmt.Fprintf(os.Stderr, "Revoke access key %s? [y/N] ", args[0])
				var answer string
				_, _ = fmt.Scanln(&answer)
				if answer != "y" && answer != "Y" && answer != "yes" {
					return &ExitError{Code: exitUsage, Msg: "revoke cancelled"}
				}
			}
			c, err := opts.authClient()
			if err != nil {
				return err
			}
			if err := c.RevokeAccessKey(cmd.Context(), args[0]); err != nil {
				return err
			}
			p := opts.printer()
			if opts.json {
				return p.PrintJSON(map[string]string{"revoked": args[0]})
			}
			fmt.Fprintf(p.Out, "revoked %s\n", args[0])
			return nil
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip confirmation")
	return cmd
}

func generateAccessKey() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	// UUID v4
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
