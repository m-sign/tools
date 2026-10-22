// Command msign creates m-sign keys, signs files and verifies signatures.
package main

import (
	"os"

	"github.com/m-sign/tools/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdout, os.Stderr, os.Getenv))
}
