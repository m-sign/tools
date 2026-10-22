package cli

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
)

func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){
		"msign": func() { os.Exit(Main(os.Args[1:], os.Stdout, os.Stderr, os.Getenv)) },
	})
}

// TestScripts runs the end-to-end scripts in testdata/script. The keys in
// the scripts are the published test keys from the m-sign specification.
func TestScripts(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: "testdata/script",
		Cmds: map[string]func(ts *testscript.TestScript, neg bool, args []string){
			"exitcode": cmdExitCode,
		},
	})
}

// cmdExitCode implements "exitcode N command [args...]": it runs the command
// and fails unless it exits with status N. Its output can then be checked
// with the stdout and stderr commands.
func cmdExitCode(ts *testscript.TestScript, neg bool, args []string) {
	if neg {
		ts.Fatalf("unsupported: ! exitcode")
	}
	if len(args) < 2 {
		ts.Fatalf("usage: exitcode N command [args...]")
	}
	want, err := strconv.Atoi(args[0])
	if err != nil {
		ts.Fatalf("invalid exit code %q", args[0])
	}

	got := 0
	if err := ts.Exec(args[1], args[2:]...); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			ts.Fatalf("running %s: %v", args[1], err)
		}
		got = exitErr.ExitCode()
	}
	if got != want {
		ts.Fatalf("%s exited with status %d, want %d", args[1], got, want)
	}
}
