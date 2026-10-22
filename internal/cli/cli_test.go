package cli

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Published test keys from the m-sign specification (kat-a).
const (
	testKey       = "KEY:Aef8KiD8bThuQYp3yj8fa9UXgTjCrsEPBmI-fdmdzJqFOG66u2Jt7-2W9v8CBoVotJnc96GlXwmXEoTTXEV2KXW1J-ywL3e6Xd9vMV8"
	testPub       = "PUB:AThuQYp3ygaFaLSZ3PehpV8JlxKE01xFdil1tSfssC93ul3fbzFf"
	testEmptySig  = "SIG:AfX-JaGE2ThuQYp3yj5lhD628lINWXhOy0FW3EH4fFxe75_vO5ikhMY1JJdnDiOJoUcg7R5-yD1cRza8jR3g-A6dB1jNUVTQSwaopQk"
	testKeyIDText = "386e418a77ca"
)

// run runs the command in-process and returns its exit code and output.
func run(t *testing.T, env map[string]string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = Main(args, &out, &errOut, func(k string) string { return env[k] })
	return code, out.String(), errOut.String()
}

func TestEnvironmentKeysWithCRLF(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file+".msign", []byte(testEmptySig+"\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	env := map[string]string{
		envPrivate: testKey + "\r\n",
		envPublic:  testPub + "\r\n",
	}
	if code, out, errOut := run(t, env, "key", "id"); code != ExitOK || !strings.Contains(out, "private: "+testKeyIDText) {
		t.Errorf("key id: code %d, stdout %q, stderr %q", code, out, errOut)
	}
	if code, out, errOut := run(t, env, "verify", file); code != ExitOK || !strings.HasSuffix(out, ": OK\n") {
		t.Errorf("verify: code %d, stdout %q, stderr %q", code, out, errOut)
	}
}

func TestKeyGenerateFileModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not meaningful on Windows")
	}
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "a.key"), filepath.Join(dir, "a.pub")

	if code, _, errOut := run(t, nil, "key", "generate", "--private", priv, "--public", pub); code != ExitOK {
		t.Fatalf("key generate failed with %d: %s", code, errOut)
	}
	for path, want := range map[string]os.FileMode{priv: modePrivate, pub: modePublic} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		// The umask may only remove permissions.
		if got := info.Mode().Perm(); got&^want != 0 || got&0o600 != 0o600 {
			t.Errorf("%s: mode %04o, want %04o", filepath.Base(path), got, want)
		}
	}
}

func TestPrivateKeyPermissionWarning(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not meaningful on Windows")
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "a.key")
	if err := os.WriteFile(key, []byte(testKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if code, _, errOut := run(t, nil, "key", "id", "--private", key); code != ExitOK || errOut != "" {
		t.Errorf("mode 0600: code %d, stderr %q; want no warning", code, errOut)
	}

	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := run(t, nil, "key", "id", "--private", key)
	if code != ExitOK || !strings.Contains(errOut, "accessible by other users (mode 0644)") {
		t.Errorf("mode 0644: code %d, stderr %q; want a warning", code, errOut)
	}
}

func TestCreateNew(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")

	if err := createNew(path, []byte("one"), modePublic); err != nil {
		t.Fatalf("createNew() failed: %v", err)
	}
	err := createNew(path, []byte("two"), modePublic)
	if !errors.Is(err, fs.ErrExist) || err.Error() != path+" already exists" {
		t.Errorf("createNew(existing) = %v, want an fs.ErrExist error", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "one" {
		t.Errorf("existing file changed to %q", got)
	}

	if err := createNew(filepath.Join(dir, "missing", "file"), nil, modePublic); err == nil {
		t.Error("createNew() in a missing directory succeeded")
	}
}

func TestWriteAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.msign")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := writeFile(path, []byte("new"), modePublic, true); err != nil {
		t.Fatalf("writeFile(overwrite) failed: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "new" {
		t.Errorf("content = %q, want %q", got, "new")
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(path); info.Mode().Perm() != modePublic {
			t.Errorf("mode = %04o, want %04o", info.Mode().Perm(), modePublic)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("directory has %d entries, want only the target (temporary file left behind?)", len(entries))
	}

	if err := writeAtomic(filepath.Join(dir, "missing", "file"), nil, modePublic); err == nil {
		t.Error("writeAtomic() in a missing directory succeeded")
	}
}

func TestSignRefusesOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file+".msign", []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}

	env := map[string]string{envPrivate: testKey}
	code, _, errOut := run(t, env, "sign", "-f", file)
	if code != ExitError || !strings.Contains(errOut, "use --force") {
		t.Errorf("code %d, stderr %q; want exit 2 with a --force hint", code, errOut)
	}
	if got, _ := os.ReadFile(file + ".msign"); string(got) != "keep" {
		t.Errorf("signature file changed to %q", got)
	}
}

func TestIsTerminal(t *testing.T) {
	if isTerminal(new(bytes.Buffer)) {
		t.Error("a buffer is not a terminal")
	}
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if isTerminal(f) {
		t.Error("a regular file is not a terminal")
	}
}
