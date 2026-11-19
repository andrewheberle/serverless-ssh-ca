#!/usr/bin/env bash
# Publishes a workspace to npm unless its version is already published, so
# the Release workflow can be re-run to finish a release that failed part way
# through, such as after core was published but testing was not.
#
# Usage: publish-once.sh <workspace> [npm publish arguments...]
set -euo pipefail

workspace="$1"
shift

name="$(node -p "require('./$workspace/package.json').name")"
version="$(node -p "require('./$workspace/package.json').version")"

# npm view prints nothing for a version that is not published. If it fails
# for another reason, publishing is tried, and npm refuses to publish over a
# version that is already published
published="$(npm view "$name@$version" version 2>/dev/null || true)"
if [ "$published" = "$version" ]; then
	echo "$name@$version is already published"
	exit 0
fi

npm publish --workspace "$workspace" "$@"
