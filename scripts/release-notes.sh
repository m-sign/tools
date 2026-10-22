#!/bin/sh
# Print the CHANGELOG.md section for a release tag, e.g. "v1.0.0".
# A pre-release tag such as v1.0.0-rc.1 falls back to the 1.0.0 section.
set -eu

tag=${1:?usage: release-notes.sh TAG}
version=${tag#v}

section() {
	awk -v v="$1" '
		/^## \[/ { if (found) exit; if (index($0, "## [" v "]") == 1) { found = 1; next } }
		found { print }
	' CHANGELOG.md
}

notes=$(section "$version")
if [ -z "$(printf '%s' "$notes" | tr -d '[:space:]')" ]; then
	notes=$(section "${version%%-*}")
fi
if [ -z "$(printf '%s' "$notes" | tr -d '[:space:]')" ]; then
	echo "release-notes.sh: CHANGELOG.md has no section for $version" >&2
	exit 1
fi
printf '%s\n' "$notes"
