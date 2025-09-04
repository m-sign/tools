//go:build showversion
// +build showversion

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	versionShort bool
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Version info",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if versionShort {
			// Print only the git hash to command output writer
			if githash == "" {
				githash = "not set"
			}
			fmt.Fprintln(cmd.OutOrStdout(), githash)
			return
		}
		showVersion()
	},
}

func init() {
	versionCmd.Flags().BoolVarP(&versionShort, "short", "s", false, "print only git hash")
	rootCmd.AddCommand(versionCmd)
}
