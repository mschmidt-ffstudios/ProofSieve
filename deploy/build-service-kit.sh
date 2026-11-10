#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 3 ]]; then
    echo 'Usage: bash deploy/build-service-kit.sh DIST_DIR METADATA_DIR OUTPUT.tar.gz' >&2
    exit 2
fi

project=$(cd "$(dirname "$0")/.." && pwd)
dist=$(cd "$1" && pwd)
metadata=$(cd "$2" && pwd)
output=$3
test ! -e "$output"
commit=$(git -C "$project" rev-parse HEAD)
version=$(git -C "$project" show "$commit:openapi.json" | jq -er '.info.version')
wheel="$dist/proofsieve-$version-py3-none-any.whl"
source="$dist/proofsieve-$version.tar.gz"
lock="$metadata/requirements-linux-x86_64-py312.txt"
test -s "$wheel" && test -s "$source" && test -s "$lock"

work=$(mktemp -d "$(dirname "$output")/.proofsieve-kit.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
kit="$work/kit"
mkdir -p "$kit/dist"
git -C "$project" archive "$commit" LICENSE NOTICE README.md CONTRIBUTING.md SECURITY.md openapi.json \
    deploy docs apps examples integrations tests | tar -xf - -C "$kit"
cp "$wheel" "$source" "$kit/dist/"
cp "$metadata/candidate.json" "$metadata/runtime.json" "$lock" "$kit/"
jq -e --arg commit "$commit" '.commit == $commit and (.ref | type == "string")' \
    "$kit/candidate.json" >/dev/null
jq -e 'type == "object"' "$kit/runtime.json" >/dev/null
for artifact in "$kit/dist/$(basename "$wheel")" "$kit/dist/$(basename "$source")" "$kit/$(basename "$lock")"; do
    name=$(basename "$artifact")
    expected=$(jq -er --arg name "$name" '.sha256[$name] | strings | select(test("^[0-9a-f]{64}$"))' \
        "$kit/candidate.json")
    if [[ $(sha256sum < "$artifact" | cut -d ' ' -f 1) != "$expected" ]]; then
        printf 'Candidate checksum mismatch for %s\n' "$name" >&2
        exit 1
    fi
done
(cd "$kit"; find . -type f -print0 | sort -z | xargs -0 sha256sum) > "$work/SHA256SUMS"
mv "$work/SHA256SUMS" "$kit/"
(cd "$kit"; sha256sum --check --status SHA256SUMS)
python3 - "$kit" "$work/service-kit.tar.gz" "$output" <<'PY'
import os
import sys
import tarfile


def normalize_owner(member):
    member.uid = member.gid = 0
    member.uname = member.gname = "root"
    return member


with tarfile.open(sys.argv[2], "w:gz") as archive:
    archive.add(sys.argv[1], arcname=".", filter=normalize_owner)
os.link(sys.argv[2], sys.argv[3])
PY
