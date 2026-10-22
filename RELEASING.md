# Releasing msign

Releases are built, signed and published by the [release workflow](.github/workflows/go-release.yaml) when a `v*` tag is pushed. This document describes what to do before and after, and how the release key is handled.

## Release key

| | |
|---|---|
| Public key | `PUB:ARi1u_Ij_5AStTTLT3JfYmVFgWOS4lGPvrtqEuVLsKnsOzbh5oHZ` ([keys/release.pub](keys/release.pub)) |
| Key ID | `18b5bbf223ff` |
| Private key | GitHub secret `MSIGN_PRIVATE` in the protected `release` environment |

This is the key embedded in the v0.1.x binaries. That was confirmed on 2026-10-22: the v0.1.1 `msign-linux-amd64` contains only this public key, and its `.msign` signature verifies with it. v0.1.x clients use it to check `self-update` downloads.

Keep an offline backup of the private key, and record who holds it.

## Before tagging

1. CI is green on `master`.
2. `go.mod` requires a **released** `github.com/m-sign/msign` version, with no `replace` directives.
3. `CHANGELOG.md` has a section `## [X.Y.Z] - YYYY-MM-DD` with the user-facing changes. The workflow uses it as the release notes and fails if it is missing.
4. Optionally, dry-run the release locally with a throwaway key:

   ```bash
   msign key generate --private /tmp/t.key --public /tmp/t.pub
   MSIGN_PRIVATE="$(cat /tmp/t.key)" make release RELEASE_PUB=/tmp/t.pub VERSION=v0.0.0-dryrun
   make clean
   ```

## Tagging

```bash
git tag -s vX.Y.Z -m "msign vX.Y.Z"
git push origin vX.Y.Z
```

A tag containing `-` (for example `v1.0.0-rc.1`) is published as a pre-release. GitHub's "latest release", which v0.1.x `self-update` uses, ignores pre-releases.

## What the workflow does

1. Runs the full test workflow.
2. Runs `make release` in the protected `release` environment:
   1. builds `msign` for the host from the tagged commit (`build/host/msign`);
   2. checks that `MSIGN_PRIVATE` belongs to `keys/release.pub` (`msign key id`);
   3. cross-compiles `bin/msign-{darwin,linux,windows}-{amd64,arm64}[.exe]` with `-trimpath`;
   4. signs every binary to `<binary>.msign`;
   5. writes and signs `SHA256SUMS`;
   6. verifies every signature and checksum.
3. Creates GitHub build-provenance attestations for the binaries and `SHA256SUMS`.
4. Creates a **draft** release with the notes from `CHANGELOG.md` and uploads `bin/*`.
5. Downloads the assets again and checks them.
6. Publishes the release.

Because the release stays a draft until every asset is uploaded and checked, "latest release" never points at a release without assets.

**The asset names must not change.** v0.1.x clients look for `msign-<os>-<arch>[.exe]` and `<name>.msign`.

## After publishing

1. Check a download:

   ```bash
   gh release download vX.Y.Z --dir /tmp/rel && cd /tmp/rel
   sha256sum -c SHA256SUMS
   msign verify --public keys/release.pub SHA256SUMS
   gh attestation verify msign-linux-amd64 --repo m-sign/tools
   ```

2. For v1.0.0 only, check the upgrade path from v0.1.x in a temporary directory:

   ```bash
   curl -fsSLO https://github.com/m-sign/tools/releases/download/v0.1.1/msign-linux-amd64
   chmod +x msign-linux-amd64
   ./msign-linux-amd64 self-update download   # must report the update
   ./msign-linux-amd64 --version             # must print the new version
   ```

3. Check that `go install github.com/m-sign/tools/cmd/msign@vX.Y.Z` works and that `msign --version` prints `vX.Y.Z`.

## If something goes wrong

- Never delete, move or reuse a published tag. Fix forward with a new patch release.
- If the workflow fails before publishing, delete the draft release (`gh release delete vX.Y.Z`), fix the problem, and re-run the workflow for the tag.

## Rotating the release key

v0.1.x clients trust only the current key, but v1.x has no self-update, so a rotation affects only people who verify downloads by hand.

1. Generate the new key offline and publish its public key in `keys/` and in the README at least one release before switching.
2. Replace `MSIGN_PRIVATE` in the `release` environment and replace `keys/release.pub` in the same change.
3. Note the rotation in `CHANGELOG.md`, with both key IDs.

If the private key is ever exposed, rotate immediately, mark affected releases in their notes, and publish a security advisory.
