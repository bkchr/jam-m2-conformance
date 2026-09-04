#!/usr/bin/env bash
# Regenerates the local cargo git source `third_party/polkajam-local.git` from the
# committed vendored snapshot `third_party/polkajam` (polkajam @ 44cc3ec20 + ALPN v1 patch).
# Run after a fresh clone, or after updating third_party/polkajam.
set -euo pipefail
cd "$(dirname "$0")/.."

SNAP=third_party/polkajam
BARE=third_party/polkajam-local.git

# Fixed author/committer identity and date keep the commit hash deterministic,
# so the `rev` pin in the root Cargo.toml stays valid across regenerations.
export GIT_AUTHOR_NAME="m2-harness"
export GIT_AUTHOR_EMAIL="m2-harness@local"
export GIT_COMMITTER_NAME="m2-harness"
export GIT_COMMITTER_EMAIL="m2-harness@local"
export GIT_AUTHOR_DATE="2026-09-03T00:00:00Z"
export GIT_COMMITTER_DATE="2026-09-03T00:00:00Z"

if [ ! -d "$SNAP" ]; then
    echo "error: $SNAP missing; commit it first" >&2
    exit 1
fi

rm -rf "$BARE" /tmp/polkajam-local-work
git init -q /tmp/polkajam-local-work
cd /tmp/polkajam-local-work
git config user.email "m2-harness@local"
git config user.name "m2-harness"
git config commit.gpgsign false
cp -a "$OLDPWD/$SNAP/." .
git add -A
git -c core.autocrlf=false commit -q -m "polkajam snapshot 44cc3ec20 with jamnp-s/1 ALPN patch"
REV=$(git rev-parse HEAD)
cd "$OLDPWD"
git clone -q --bare /tmp/polkajam-local-work "$BARE"
rm -rf /tmp/polkajam-local-work
echo "regenerated $BARE at $REV"
