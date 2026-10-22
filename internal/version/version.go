// Package version reports the version of the msign binary.
//
// Release builds set the variables with the linker:
//
//	-ldflags "-X github.com/m-sign/tools/internal/version.Version=v1.0.0
//	          -X github.com/m-sign/tools/internal/version.Commit=<git hash>
//	          -X github.com/m-sign/tools/internal/version.Date=<RFC 3339 time>"
//
// Builds without these flags, such as "go install", fall back to the module
// version and VCS information recorded by the Go toolchain.
package version

import (
	"runtime"
	"runtime/debug"
	"strings"
)

// Values set at link time; empty when not set.
var (
	Version string // release version, e.g. "v1.0.0"
	Commit  string // git commit hash
	Date    string // commit time, RFC 3339
)

// readBuildInfo is replaced in tests.
var readBuildInfo = debug.ReadBuildInfo

// Info describes the running binary.
type Info struct {
	Version   string // release or module version; "devel" when unknown
	Commit    string // git commit hash, may be empty
	Date      string // commit time, may be empty
	Modified  bool   // built from a modified working tree
	GoVersion string
	Platform  string // GOOS/GOARCH
}

// Get returns the version information of the running binary.
func Get() Info {
	info := Info{
		Version:   Version,
		Commit:    Commit,
		Date:      Date,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}

	if bi, ok := readBuildInfo(); ok {
		if info.Version == "" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			info.Version = bi.Main.Version
		}
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if info.Commit == "" {
					info.Commit = s.Value
				}
			case "vcs.time":
				if info.Date == "" {
					info.Date = s.Value
				}
			case "vcs.modified":
				info.Modified = s.Value == "true"
			}
		}
	}

	if info.Version == "" {
		info.Version = "devel"
	}
	return info
}

// String returns a one-line description, for example
// "v1.0.0 (commit 1a2b3c4d5e6f, 2026-10-21T10:00:00Z, go1.27.2 linux/amd64)".
func (i Info) String() string {
	details := make([]string, 0, 3)
	if i.Commit != "" {
		commit := "commit " + shortCommit(i.Commit)
		if i.Modified {
			commit += "-dirty"
		}
		details = append(details, commit)
	}
	if i.Date != "" {
		details = append(details, i.Date)
	}
	details = append(details, i.GoVersion+" "+i.Platform)
	return i.Version + " (" + strings.Join(details, ", ") + ")"
}

func shortCommit(c string) string {
	if len(c) > 12 {
		return c[:12]
	}
	return c
}
