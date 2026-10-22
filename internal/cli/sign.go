package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/m-sign/msign"
	"github.com/spf13/cobra"
)

func newSignCommand(env *Env) *cobra.Command {
	var (
		privateFile   string
		signatureFile string
		toFile        bool
		force         bool
		quiet         bool
	)

	cmd := &cobra.Command{
		Use:   "sign [flags] FILE...",
		Short: "Sign files",
		Long: `Sign one or more files with a private key.

The private key is read from --private FILE, or from MSIGN_PRIVATE.

By default each signature is printed to standard output as
"Signature for FILE: SIG:...". With --to-file, it is saved next to the file
as FILE.msign; with --signature, it is saved to the given path (one input file
only). Existing signature files are only replaced with --force, and then
atomically.`,
		Example: `  msign sign --private release.key --to-file msign-linux-amd64
  MSIGN_PRIVATE="$SECRET" msign sign -f dist/*`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if signatureFile != "" && len(args) != 1 {
				return errors.New("--signature can only be used with exactly one file")
			}

			priv, err := loadPrivateKey(cmd, env, privateFile)
			if err != nil {
				return err
			}

			for _, path := range args {
				sig, err := signFile(priv, path)
				if err != nil {
					return fmt.Errorf("%s: %w", path, err)
				}

				out := signatureFile
				if out == "" && toFile {
					out = path + ".msign"
				}
				if out == "" {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Signature for %s: %s", path, itemText(sig)); err != nil {
						return err
					}
					continue
				}

				if err := writeFile(out, itemText(sig), modePublic, force); err != nil {
					if errors.Is(err, fs.ErrExist) {
						return fmt.Errorf("%w (use --force to replace it)", err)
					}
					return err
				}
				status(cmd, quiet, "Signature for %s saved to %s", path, out)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&privateFile, "private", "", "read the private key from `FILE` (default: $"+envPrivate+")")
	cmd.Flags().BoolVarP(&toFile, "to-file", "f", false, "save each signature to FILE.msign instead of printing it")
	cmd.Flags().StringVar(&signatureFile, "signature", "", "save the signature to `PATH` (implies --to-file; one input file only)")
	cmd.Flags().BoolVar(&force, "force", false, "replace existing signature files")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "do not print status messages")
	return cmd
}

func signFile(priv msign.PrivateKey, path string) (msign.Signature, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only

	return priv.Sign(f)
}
