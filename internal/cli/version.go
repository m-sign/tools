package cli

import (
	"fmt"

	"github.com/m-sign/tools/internal/version"
	"github.com/spf13/cobra"
)

func newVersionCommand() *cobra.Command {
	var short bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info := version.Get()
			out := cmd.OutOrStdout()
			if short {
				_, err := fmt.Fprintln(out, info.Version)
				return err
			}

			commit := info.Commit
			if commit == "" {
				commit = "unknown"
			} else if info.Modified {
				commit += " (modified)"
			}
			date := info.Date
			if date == "" {
				date = "unknown"
			}
			_, err := fmt.Fprintf(out, "msign %s\n  commit:   %s\n  date:     %s\n  go:       %s\n  platform: %s\n",
				info.Version, commit, date, info.GoVersion, info.Platform)
			return err
		},
	}
	cmd.Flags().BoolVarP(&short, "short", "s", false, "print only the version")
	return cmd
}
