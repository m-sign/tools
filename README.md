# github.com/m-sign/tools
[![License][license-img]][license] [![Actions Status][action-img]][action] [![PkgGoDev][pkggodev-img]][pkggodev] [![Go Report Card][goreport-img]][goreport] [![Coverage Status][codecov-img]][codecov]

## Overview
This repository contains `msign`, a command-line tool that creates m-sign keys, signs files and verifies signatures.

Keys and signatures are single-line text items (`KEY:…`, `PUB:…`, `SIG:…`) defined by the [m-sign data formats specification](https://github.com/m-sign/specs/blob/v1.0.0/format.md). Because they are one line of text, they fit in files, environment variables and CI secrets. The Go library is [m-sign/msign](https://github.com/m-sign/msign).

## Installation
Download the binary for your platform from [GitHub Releases](https://github.com/m-sign/tools/releases), then verify it before use:

```bash
VERSION=v1.0.0
BASE=https://github.com/m-sign/tools/releases/download/$VERSION
curl -fsSLO "$BASE/msign-linux-amd64"
curl -fsSLO "$BASE/SHA256SUMS"
curl -fsSLO "$BASE/SHA256SUMS.msign"

# 1. Check that the binary was built by this repository's release workflow:
gh attestation verify msign-linux-amd64 --repo m-sign/tools

# 2. Check the checksum:
sha256sum --ignore-missing -c SHA256SUMS

chmod +x msign-linux-amd64 && mv msign-linux-amd64 /usr/local/bin/msign
```

Once you have a trusted `msign`, you can also check the release signature directly. The [release public key](keys/release.pub) is:

```
PUB:ARi1u_Ij_5AStTTLT3JfYmVFgWOS4lGPvrtqEuVLsKnsOzbh5oHZ    (key ID 18b5bbf223ff)
```

```bash
msign verify --public keys/release.pub SHA256SUMS
```

To build from source instead (Go 1.26 or later):

```bash
go install github.com/m-sign/tools/cmd/msign@latest
```

## Quick start
```bash
# Create a key pair. The private key file gets mode 0600.
msign key generate --private release.key --public release.pub

# Sign a file: writes app.tar.gz.msign next to it.
msign sign --private release.key --to-file app.tar.gz

# Verify it.
msign verify --public release.pub app.tar.gz
# app.tar.gz: OK
```

## Using in CI
Store the private key (the `KEY:…` line of `release.key`) as a CI secret and expose it as `MSIGN_PRIVATE`. Publish the public key, or store it as `MSIGN_PUBLIC`.

```yaml
# GitHub Actions
- name: Sign artifacts
  env:
    MSIGN_PRIVATE: ${{ secrets.MSIGN_PRIVATE }}
  run: |
    msign key id --public release.pub   # fails if the secret does not match the public key
    msign sign -q --to-file dist/*
- name: Verify artifacts
  env:
    MSIGN_PUBLIC: ${{ vars.MSIGN_PUBLIC }}
  run: msign verify -q dist/*
```

## Command reference
```
msign key generate [--private FILE] [--public FILE]
msign key public   [--private FILE] [--public FILE]
msign key id       [--private FILE] [--public FILE]
msign sign   [--private FILE] [-f|--to-file] [--force] [--signature FILE] [-q|--quiet] FILE...
msign verify [--public FILE] [--signature FILE] [-q|--quiet] FILE...
msign version [-s|--short]
msign completion bash|zsh|fish|powershell
```

Run `msign <command> --help` for details and examples.

| Command | What it does |
|---|---|
| `key generate` | Creates a key pair. Without files, prints the `KEY:` line and then the `PUB:` line to standard output. Never overwrites files. |
| `key public` | Prints, or saves with `--public`, the public key of a private key. |
| `key id` | Prints the key ID of a key. With both a private and a public key, checks that they belong together. |
| `sign` | Prints `Signature for FILE: SIG:…`, or with `--to-file` saves `FILE.msign`. `--signature PATH` chooses the path (one file only). Existing signature files are replaced only with `--force`, and then atomically. |
| `verify` | Checks `FILE` against `FILE.msign` (or `--signature PATH`) and prints `FILE: OK` or `FILE: FAILED (reason)` for every file. |

**Keys.** The private key is read from `--private FILE`, otherwise from the `MSIGN_PRIVATE` environment variable. The public key is read from `--public FILE`, otherwise from `MSIGN_PUBLIC`. In variables, the trailing newline is optional.

**Output.** Standard output carries only data: keys, signatures, verification results, key IDs and version information. Status messages, warnings and errors go to standard error. `-q` hides status messages and `verify`'s OK lines.

**Exit codes.**

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Verification failed: a signature is invalid, made by another key, missing or malformed, or a file could not be read; or `key id` found that the keys do not belong together |
| 2 | Any other error: invalid usage, missing or invalid key, I/O error while signing or writing |

## Key management
- A `KEY:` item is a **plaintext** private key. Keep key files at mode `0600`; `msign` warns when a private key file is readable by other users. In CI, store the key in the secret store, never in the repository.
- Prefer `--private FILE` over printing the private key to a terminal or log. `msign key generate` warns when it writes a private key to a terminal.
- On Windows PowerShell 5.1, `>` writes UTF-16 files that `msign` cannot read. Use `--private` and `--public` instead of redirecting output.
- A key ID is only a hint for choosing a key: always verify with a public key you obtained from a trusted source.
- To rotate a key, publish the new public key alongside the old one before you start signing with the new key.

## Upgrading from 0.1.x
- `self-update` was removed. Download new versions from GitHub Releases or use `go install`. If you run v0.1.x, `msign self-update download` still upgrades you to v1.0.0 one last time.
- Status messages moved from standard output to standard error: `key generate` without files now prints only the two key lines.
- `verify` checks every file, even after a failure, and prints `FILE: OK` or `FILE: FAILED (reason)`. It exits with status 1 for verification failures and status 2 for other errors; before, every error exited with 1.
- `version --short` prints the version instead of the git hash, and `msign --version` was added.
- Signature parsing is stricter: malformed files that v0.1.x accepted are now reported as malformed.

See the [changelog](CHANGELOG.md) for details.

## Contributing
We encourage and support an active, healthy community of contributors &mdash;
including you! Details are in the [contribution guide](CONTRIBUTING.md) and
the [code of conduct](CODE_OF_CONDUCT.md). Report security issues as described in [SECURITY.md](SECURITY.md).

[![Contributor Covenant][covenant-img]](CODE_OF_CONDUCT.md)

[covenant-img]: https://img.shields.io/badge/contributor%20covenant-v2.1%20adopted-ff69b4.svg
[license-img]: https://img.shields.io/badge/license-MIT-blue.svg
[license]: LICENSE
[action-img]: https://github.com/m-sign/tools/actions/workflows/go-test.yaml/badge.svg
[action]: https://github.com/m-sign/tools/actions/workflows/go-test.yaml
[goreport-img]: https://goreportcard.com/badge/github.com/m-sign/tools
[goreport]: https://goreportcard.com/report/github.com/m-sign/tools
[codecov-img]: https://codecov.io/gh/m-sign/tools/branch/master/graph/badge.svg
[codecov]: https://codecov.io/gh/m-sign/tools
[pkggodev-img]: https://pkg.go.dev/badge/github.com/m-sign/tools
[pkggodev]: https://pkg.go.dev/github.com/m-sign/tools
