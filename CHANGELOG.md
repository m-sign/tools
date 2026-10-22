# Changelog

All notable changes to `msign` are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [semantic versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] - unreleased

Keys and signatures created by 0.1.x stay valid: the file format is unchanged.

### Removed
- The `self-update` command. Download releases from GitHub or use `go install`. Running `self-update download` from v0.1.x still upgrades to this release.

### Breaking
- Status messages go to standard error. Standard output carries only data, so `msign key generate` without files prints just the `KEY:` and `PUB:` lines.
- Exit codes: `1` now means only "verification failed" (or a key pair that does not match in `key id`); every other error exits with `2`. Before, every error exited with `1`.
- `verify` prints `FILE: OK` or `FILE: FAILED (reason)` instead of `Verifying FILE : OK`.
- `version --short` prints the version instead of the git hash.
- Key and signature parsing follows the m-sign specification 1.0.0 and is stricter: non-canonical or malformed items are rejected.

### Added
- `verify` checks every file even after a failure and reports a reason for each failure.
- `--signature PATH` for `sign` and `verify`, for a signature file with a custom name.
- `-q/--quiet` for `sign` and `verify`.
- `msign --version`; version information also works for `go install` builds.
- `key id` with both a private and a public key checks that they belong together, which is useful before signing in CI.
- Warnings when a private key file is readable by other users, and when a private key is printed to a terminal.
- Release assets now include `SHA256SUMS`, its signature `SHA256SUMS.msign` and GitHub build-provenance attestations. The release public key is published in `keys/release.pub`.

### Fixed
- Key files are created exclusively and never overwritten, even if a file appears while the command runs. Public key files get mode `0644` (was `0600`).
- `key generate` no longer leaves empty or half-written key files behind.
- `sign --force` replaces signature files atomically, and write errors are reported.
- Usage errors no longer depend on the program name (`msign.exe` on Windows).

### Security
- Release binaries are signed by the `msign` built from the release commit, not by a previously published `msign`.
- Releases are published only after all assets are uploaded and checked.
- Private keys whose public half does not match the seed are rejected (via msign v1.0.0).

## [0.1.1] - 2025-09-04

## [0.1.0] - 2023-11-19

- First release.
