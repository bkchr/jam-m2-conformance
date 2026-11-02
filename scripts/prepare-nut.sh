#!/usr/bin/env bash
# Prepares the polkajam node-under-test binary.
#
# The workspace depends on polkajam's library crates as ordinary git
# dependencies (see the root Cargo.toml). This script is only needed to obtain
# the `polkajam` *binary* used as the NUT.
#
# The revision is read from Cargo.toml rather than repeated here. The oracle
# grades the node under test, so unless a run deliberately sets out to compare
# revisions, the two must be the same engine -- and a second copy of the
# revision is a second thing to forget to update.
#
# The checkout lives in third_party/ which is gitignored: nothing from polkajam
# is committed to this repository.
set -euo pipefail
cd "$(dirname "$0")/.."

REPO=${POLKAJAM_REPO:-ssh://git@github.com/paritytech/polkajam.git}
DEST=third_party/polkajam

PINNED=$(sed -n 's/^jam-node = .*rev = "\([0-9a-f]\{40\}\)".*/\1/p' Cargo.toml | head -1)
if [ -z "$PINNED" ]; then
    echo "could not read the polkajam revision from Cargo.toml" >&2
    exit 1
fi

REV=${POLKAJAM_REV:-$PINNED}
if [ "$REV" != "$PINNED" ]; then
    echo "WARNING: building the NUT from ${REV}, while the reference oracle is" >&2
    echo "         pinned to ${PINNED}. The node under test and the engine that" >&2
    echo "         grades it will be different builds." >&2
fi

if [ -d "$DEST/.git" ]; then
    echo "reusing existing checkout at $DEST"
    git -C "$DEST" fetch --quiet origin "$REV" 2>/dev/null || git -C "$DEST" fetch --quiet origin
    git -C "$DEST" checkout --quiet --force "$REV"
    git -C "$DEST" clean -qfd
else
    mkdir -p third_party
    rm -rf "$DEST"
    git clone --quiet "$REPO" "$DEST"
    git -C "$DEST" checkout --quiet --force "$REV"
fi
echo "polkajam at $REV"

# polkavm chooses a sandbox at run time, and the Linux one needs userfaultfd.
# Some hosts deny that to unprivileged processes (vm.unprivileged_userfaultfd=0)
# and offer no sudo, which leaves no way to execute a work package. Building the
# generic sandbox in gives POLKAVM_SANDBOX=generic something to select; it is
# off by default because it is slower and most hosts do not need it.
#
# This is a one-line feature flip, made here rather than carried in patches/.
# A patch file pins the polkavm version in its own context and so rots at every
# re-pin -- silently, since the script that applied it was never run in CI.
# That is exactly how the two patches this replaced came to be both stale and
# malformed.
if [ "${POLKAJAM_GENERIC_SANDBOX:-0}" = "1" ]; then
    # `|| true`: grep exits 1 when it matches nothing, and under `set -o pipefail`
    # that would abort the script before the explanation below is printed.
    line=$(grep -n '^polkavm = {.*features = \[\] *}' "$DEST/Cargo.toml" | head -1 | cut -d: -f1 || true)
    if [ -z "$line" ]; then
        echo "no polkavm dependency line to patch in $DEST/Cargo.toml -- upstream" >&2
        echo "changed its shape; update this script rather than skipping the flip" >&2
        exit 1
    fi
    sed -i "${line}s/features = \[\]/features = [\"generic-sandbox\"]/" "$DEST/Cargo.toml"
    echo "enabled polkavm's generic sandbox; run the NUT with POLKAVM_SANDBOX=generic"
fi

cargo build --release --manifest-path "$DEST/Cargo.toml" --bin polkajam

echo
echo "NUT binary: $DEST/target/release/polkajam"
echo "add it to PATH before a real-surface run:"
echo "  export PATH=\"\$PWD/$DEST/target/release:\$PATH\""
