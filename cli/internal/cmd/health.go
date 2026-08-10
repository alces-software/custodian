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

	"github.com/spf13/cobra"
)

func newHealthCmd(opts *rootOptions) *cobra.Command {
	var ready bool
	cmd := &cobra.Command{
		Use:   "health",
		Short: "Check Custodian liveness (and optionally readiness)",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := opts.urlClient()
			if err != nil {
				return err
			}
			p := opts.printer()
			ctx := cmd.Context()

			hz, err := c.Healthz(ctx)
			if err != nil {
				return err
			}
			if !ready {
				if opts.json {
					return p.PrintJSON(hz)
				}
				fmt.Fprintf(p.Out, "health: %s\n", hz.Status)
				return nil
			}

			rz, err := c.Readyz(ctx)
			if err != nil {
				return err
			}
			if opts.json {
				return p.PrintJSON(map[string]string{
					"health": hz.Status,
					"ready":  rz.Status,
				})
			}
			fmt.Fprintf(p.Out, "health: %s\nready:  %s\n", hz.Status, rz.Status)
			if rz.Status != "ready" {
				return &ExitError{Code: exitFail, Msg: "not ready"}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&ready, "ready", false, "Also check /readyz")
	return cmd
}
