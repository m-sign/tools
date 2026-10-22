package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/m-sign/msign"
	"github.com/spf13/cobra"
)

func newKeyCommand(env *Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Generate keys and inspect them",
	}
	cmd.AddCommand(
		newKeyGenerateCommand(),
		newKeyPublicCommand(env),
		newKeyIDCommand(env),
	)
	return cmd
}

func newKeyGenerateCommand() *cobra.Command {
	var privateFile, publicFile string

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a new key pair",
		Long: `Generate a new key pair.

Without --private and --public, the private key (KEY:...) and then the public
key (PUB:...) are written to standard output, one per line. The key ID and
status messages go to standard error.

Key files are never overwritten. The private key file is created with mode
0600 and the public key file with mode 0644.`,
		Example: `  msign key generate --private release.key --public release.pub`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if privateFile != "" && privateFile == publicFile {
				return errors.New("--private and --public must name different files")
			}
			// Fail before printing anything if a key file exists. createNew
			// still refuses to overwrite, in case a file appears meanwhile.
			for _, path := range []string{privateFile, publicFile} {
				if path == "" {
					continue
				}
				if err := checkNotExist(path); err != nil {
					return err
				}
			}

			priv, pub, err := msign.NewPrivateKey()
			if err != nil {
				return err
			}
			status(cmd, false, "Key ID: %s", priv.ID())

			stdout := cmd.OutOrStdout()
			if privateFile != "" {
				if err := createNew(privateFile, itemText(priv), modePrivate); err != nil {
					return err
				}
				status(cmd, false, "Private key saved to %s", privateFile)
			} else {
				if isTerminal(stdout) {
					warn(cmd, "writing the private key to the terminal; prefer --private FILE")
				}
				if _, err := stdout.Write(itemText(priv)); err != nil {
					return err
				}
			}

			if publicFile != "" {
				if err := createNew(publicFile, itemText(pub), modePublic); err != nil {
					if privateFile != "" {
						_ = os.Remove(privateFile) // do not leave half a key pair behind
					}
					return err
				}
				status(cmd, false, "Public key saved to %s", publicFile)
				return nil
			}
			_, err = stdout.Write(itemText(pub))
			return err
		},
	}
	cmd.Flags().StringVar(&privateFile, "private", "", "save the private key to `FILE` (default: standard output)")
	cmd.Flags().StringVar(&publicFile, "public", "", "save the public key to `FILE` (default: standard output)")
	return cmd
}

func newKeyPublicCommand(env *Env) *cobra.Command {
	var privateFile, publicFile string

	cmd := &cobra.Command{
		Use:   "public",
		Short: "Print the public key of a private key",
		Long: `Print the public key that belongs to a private key.

The private key is read from --private FILE, or from MSIGN_PRIVATE. The
public key is written to standard output, or to --public FILE, which must not
exist yet.`,
		Example: `  msign key public --private release.key --public release.pub`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			priv, err := loadPrivateKey(cmd, env, privateFile)
			if err != nil {
				return err
			}

			text := itemText(priv.Public())
			if publicFile == "" {
				_, err = cmd.OutOrStdout().Write(text)
				return err
			}
			if err := createNew(publicFile, text, modePublic); err != nil {
				return err
			}
			status(cmd, false, "Public key saved to %s", publicFile)
			return nil
		},
	}
	cmd.Flags().StringVar(&privateFile, "private", "", "read the private key from `FILE` (default: $"+envPrivate+")")
	cmd.Flags().StringVar(&publicFile, "public", "", "save the public key to `FILE` (default: standard output)")
	return cmd
}

func newKeyIDCommand(env *Env) *cobra.Command {
	var privateFile, publicFile string

	cmd := &cobra.Command{
		Use:   "id",
		Short: "Print the key ID of a key, or check that a key pair matches",
		Long: `Print the key ID of a private or public key.

With one key, the key ID is printed alone. With both a private and a public
key, both IDs are printed and the command exits with status 1 if they differ.
This checks that a private key (for example a CI secret) matches a published
public key.

Keys are read from --private FILE and --public FILE, or from MSIGN_PRIVATE
and MSIGN_PUBLIC.`,
		Example: `  msign key id --public release.pub
  MSIGN_PRIVATE="$SECRET" msign key id --public release.pub`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			havePrivate, havePublic := hasPrivateKey(env, privateFile), hasPublicKey(env, publicFile)
			if !havePrivate && !havePublic {
				return errors.New("no key: use --private FILE or --public FILE, or set " + envPrivate + " or " + envPublic)
			}

			var privID, pubID msign.KeyID
			if havePrivate {
				priv, err := loadPrivateKey(cmd, env, privateFile)
				if err != nil {
					return err
				}
				privID = priv.ID()
			}
			if havePublic {
				pub, err := loadPublicKey(env, publicFile)
				if err != nil {
					return err
				}
				pubID = pub.ID()
			}

			stdout := cmd.OutOrStdout()
			switch {
			case !havePublic:
				fmt.Fprintln(stdout, privID)
			case !havePrivate:
				fmt.Fprintln(stdout, pubID)
			default:
				fmt.Fprintln(stdout, "private:", privID)
				fmt.Fprintln(stdout, "public: ", pubID)
				if privID.String() != pubID.String() {
					return fmt.Errorf("%w: the private and public keys do not belong together", errVerificationFailed)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&privateFile, "private", "", "read the private key from `FILE` (default: $"+envPrivate+")")
	cmd.Flags().StringVar(&publicFile, "public", "", "read the public key from `FILE` (default: $"+envPublic+")")
	return cmd
}
