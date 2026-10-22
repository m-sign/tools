// Package cli implements the msign command-line interface.
package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/m-sign/tools/internal/version"
	"github.com/spf13/cobra"
)

// Exit codes of the msign command.
const (
	ExitOK           = 0 // success
	ExitVerifyFailed = 1 // a signature did not verify, or a key pair does not match
	ExitError        = 2 // any other error: usage, keys, I/O
)

// Environment variables that hold keys.
const (
	envPrivate = "MSIGN_PRIVATE"
	envPublic  = "MSIGN_PUBLIC"
)

// errVerificationFailed marks errors that exit with ExitVerifyFailed.
var errVerificationFailed = errors.New("verification failed")

// Env is the process environment a command runs in.
type Env struct {
	Stdout io.Writer
	Stderr io.Writer
	Getenv func(key string) string
}

// Main runs the msign command with args (without the program name) and
// returns its exit code.
func Main(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	root := NewRootCommand(&Env{Stdout: stdout, Stderr: stderr, Getenv: getenv})
	root.SetArgs(args)

	err := root.Execute()
	if err == nil {
		return ExitOK
	}

	fmt.Fprintln(stderr, "msign:", err)
	if errors.Is(err, errVerificationFailed) {
		return ExitVerifyFailed
	}
	return ExitError
}

// NewRootCommand returns the msign command tree.
func NewRootCommand(env *Env) *cobra.Command {
	root := &cobra.Command{
		Use:   "msign",
		Short: "msign creates keys, signs files and verifies signatures",
		Long: `msign creates m-sign keys, signs files and verifies signatures.

Keys and signatures are single-line text items: KEY:... (private key),
PUB:... (public key) and SIG:... (signature). A key can be read from a file
(--private, --public) or from the MSIGN_PRIVATE and MSIGN_PUBLIC environment
variables.

Exit codes:
  0  success
  1  verification failed: a signature is invalid, missing or malformed, or
     a key pair does not match
  2  any other error: invalid usage, unreadable or invalid key, I/O error`,
		Version:       version.Get().String(),
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.SetOut(env.Stdout)
	root.SetErr(env.Stderr)
	root.SetVersionTemplate("msign {{.Version}}\n")

	root.AddCommand(
		newKeyCommand(env),
		newSignCommand(env),
		newVerifyCommand(env),
		newVersionCommand(),
	)
	return root
}

// status prints a progress message to stderr unless quiet is set.
func status(cmd *cobra.Command, quiet bool, format string, args ...any) {
	if !quiet {
		fmt.Fprintf(cmd.ErrOrStderr(), format+"\n", args...)
	}
}

// warn prints a warning to stderr.
func warn(cmd *cobra.Command, format string, args ...any) {
	fmt.Fprintf(cmd.ErrOrStderr(), "msign: warning: "+format+"\n", args...)
}
