package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/m-sign/msign"
	"github.com/spf13/cobra"
)

// File modes of the files msign creates.
const (
	modePrivate os.FileMode = 0o600
	modePublic  os.FileMode = 0o644 // public keys and signatures
)

// hasPrivateKey reports whether a private key source is configured.
func hasPrivateKey(env *Env, path string) bool {
	return path != "" || env.Getenv(envPrivate) != ""
}

// hasPublicKey reports whether a public key source is configured.
func hasPublicKey(env *Env, path string) bool {
	return path != "" || env.Getenv(envPublic) != ""
}

// loadPrivateKey reads the private key from path, or from MSIGN_PRIVATE when
// path is empty.
func loadPrivateKey(cmd *cobra.Command, env *Env, path string) (msign.PrivateKey, error) {
	if path == "" {
		value := env.Getenv(envPrivate)
		if value == "" {
			return nil, errors.New("no private key: use --private FILE or set " + envPrivate)
		}
		key, err := msign.ParsePrivateKey(value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", envPrivate, err)
		}
		return key, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only

	warnIfShared(cmd, f, path)

	key, err := msign.ImportPrivateKey(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return key, nil
}

// loadPublicKey reads the public key from path, or from MSIGN_PUBLIC when
// path is empty.
func loadPublicKey(env *Env, path string) (msign.PublicKey, error) {
	if path == "" {
		value := env.Getenv(envPublic)
		if value == "" {
			return nil, errors.New("no public key: use --public FILE or set " + envPublic)
		}
		key, err := msign.ParsePublicKey(value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", envPublic, err)
		}
		return key, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only

	key, err := msign.ImportPublicKey(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return key, nil
}

// warnIfShared warns when a private key file can be read or written by
// other users. File modes are not meaningful on Windows.
func warnIfShared(cmd *cobra.Command, f *os.File, path string) {
	if runtime.GOOS == "windows" {
		return
	}
	info, err := f.Stat()
	if err != nil {
		return
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		warn(cmd, "private key file %s is accessible by other users (mode %04o); run: chmod 600 %s", path, perm, path)
	}
}

// writeFile writes data to path. Without overwrite it refuses to replace an
// existing file; with overwrite it replaces the file atomically.
func writeFile(path string, data []byte, perm os.FileMode, overwrite bool) error {
	if overwrite {
		return writeAtomic(path, data, perm)
	}
	return createNew(path, data, perm)
}

// createNew creates path, which must not exist, and writes data to it. On
// failure the partly written file is removed.
func createNew(path string, data []byte, perm os.FileMode) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return &fileExistsError{path}
		}
		return err
	}

	_, err = f.Write(data)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// fileExistsError reports a file that msign refuses to overwrite. It matches
// fs.ErrExist.
type fileExistsError struct {
	path string
}

func (e *fileExistsError) Error() string { return e.path + " already exists" }
func (e *fileExistsError) Unwrap() error { return fs.ErrExist }

// checkNotExist returns a fileExistsError if path exists.
func checkNotExist(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return &fileExistsError{path}
	}
	return nil
}

// writeAtomic writes data to a temporary file next to path and renames it
// over path, so that readers see either the old or the new content.
func writeAtomic(path string, data []byte, perm os.FileMode) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err = tmp.Write(data); err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Chmod(tmpName, perm)
	}
	if err == nil {
		err = os.Rename(tmpName, path)
	}
	if err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// itemText returns the text encoding of an item, with its trailing newline.
func itemText(item msign.Item) []byte {
	var buf textBuffer
	_ = msign.Export(&buf, item) // writing to memory cannot fail
	return buf
}

type textBuffer []byte

func (b *textBuffer) Write(p []byte) (int, error) {
	*b = append(*b, p...)
	return len(p), nil
}

// isTerminal reports whether w is a terminal.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
