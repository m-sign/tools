package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/m-sign/msign"
	"github.com/spf13/cobra"
)

func newVerifyCommand(env *Env) *cobra.Command {
	var (
		publicFile    string
		signatureFile string
		quiet         bool
	)

	cmd := &cobra.Command{
		Use:   "verify [flags] FILE...",
		Short: "Verify signatures of files",
		Long: `Verify the signatures of one or more files.

The public key is read from --public FILE, or from MSIGN_PUBLIC. The signature
of FILE is read from FILE.msign, or from --signature PATH (one input file
only).

Every file is checked, even after a failure, and reported on standard output
as "FILE: OK" or "FILE: FAILED (reason)". The command exits with status 1 if
any file failed verification.`,
		Example: `  msign verify --public release.pub msign-linux-amd64
  MSIGN_PUBLIC="PUB:..." msign verify -q dist/*`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if signatureFile != "" && len(args) != 1 {
				return errors.New("--signature can only be used with exactly one file")
			}

			pub, err := loadPublicKey(env, publicFile)
			if err != nil {
				return err
			}

			failed := 0
			for _, path := range args {
				sigPath := signatureFile
				if sigPath == "" {
					sigPath = path + ".msign"
				}

				reason := verifyFile(pub, path, sigPath)
				if reason != "" {
					failed++
					fmt.Fprintf(cmd.OutOrStdout(), "%s: FAILED (%s)\n", path, reason)
					continue
				}
				if !quiet {
					fmt.Fprintf(cmd.OutOrStdout(), "%s: OK\n", path)
				}
			}

			if failed > 0 {
				return fmt.Errorf("%w: %d of %d files", errVerificationFailed, failed, len(args))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&publicFile, "public", "", "read the public key from `FILE` (default: $"+envPublic+")")
	cmd.Flags().StringVar(&signatureFile, "signature", "", "read the signature from `PATH` (default: FILE.msign; one input file only)")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "print only failures")
	return cmd
}

// verifyFile verifies one file and returns why it failed, or "" if the
// signature is valid.
func verifyFile(pub msign.PublicKey, path, sigPath string) string {
	sigFile, err := os.Open(sigPath)
	if errors.Is(err, fs.ErrNotExist) {
		return "signature file not found"
	}
	if err != nil {
		return "cannot read signature file"
	}
	defer func() { _ = sigFile.Close() }() // read-only

	sig, err := msign.ImportSignature(sigFile)
	if err != nil {
		return "malformed signature file"
	}

	f, err := os.Open(path)
	if err != nil {
		return "cannot read file"
	}
	defer func() { _ = f.Close() }() // read-only

	err = pub.Verify(f, sig)
	switch {
	case err == nil:
		return ""
	case errors.Is(err, msign.ErrKeyIDMismatch):
		return "key id mismatch"
	case errors.Is(err, msign.ErrInvalidSignature):
		return "invalid signature"
	default:
		return "cannot read file"
	}
}
