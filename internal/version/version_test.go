package version

import (
	"runtime/debug"
	"strings"
	"testing"
)

func withBuildInfo(t *testing.T, bi *debug.BuildInfo, ok bool) {
	t.Helper()
	saved := readBuildInfo
	readBuildInfo = func() (*debug.BuildInfo, bool) { return bi, ok }
	t.Cleanup(func() { readBuildInfo = saved })
}

func withLinkerValues(t *testing.T, version, commit, date string) {
	t.Helper()
	v, c, d := Version, Commit, Date
	Version, Commit, Date = version, commit, date
	t.Cleanup(func() { Version, Commit, Date = v, c, d })
}

func TestLinkerValuesWin(t *testing.T) {
	withLinkerValues(t, "v1.2.3", "0123456789abcdef0123", "2026-10-21T10:00:00Z")
	withBuildInfo(t, &debug.BuildInfo{
		Main:     debug.Module{Version: "v9.9.9"},
		Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "ffff"}, {Key: "vcs.time", Value: "2000-01-01T00:00:00Z"}},
	}, true)

	info := Get()
	if info.Version != "v1.2.3" || info.Commit != "0123456789abcdef0123" || info.Date != "2026-10-21T10:00:00Z" {
		t.Errorf("Get() = %+v, want the linker values", info)
	}
	if s := info.String(); !strings.HasPrefix(s, "v1.2.3 (commit 0123456789ab, 2026-10-21T10:00:00Z, go") {
		t.Errorf("String() = %q", s)
	}
}

func TestBuildInfoFallback(t *testing.T) {
	withLinkerValues(t, "", "", "")
	withBuildInfo(t, &debug.BuildInfo{
		Main: debug.Module{Version: "v1.0.0"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "abc123"},
			{Key: "vcs.time", Value: "2026-10-21T10:00:00Z"},
			{Key: "vcs.modified", Value: "true"},
		},
	}, true)

	info := Get()
	if info.Version != "v1.0.0" || info.Commit != "abc123" || info.Date != "2026-10-21T10:00:00Z" || !info.Modified {
		t.Errorf("Get() = %+v, want values from the build info", info)
	}
	if s := info.String(); !strings.Contains(s, "commit abc123-dirty") {
		t.Errorf("String() = %q, want a dirty commit", s)
	}
}

func TestUnknownVersion(t *testing.T) {
	withLinkerValues(t, "", "", "")
	for _, tt := range []struct {
		name string
		bi   *debug.BuildInfo
		ok   bool
	}{
		{"no build info", nil, false},
		{"devel module", &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			withBuildInfo(t, tt.bi, tt.ok)
			info := Get()
			if info.Version != "devel" {
				t.Errorf("Version = %q, want devel", info.Version)
			}
			if s := info.String(); strings.Contains(s, "commit") {
				t.Errorf("String() = %q, want no commit", s)
			}
		})
	}
}
