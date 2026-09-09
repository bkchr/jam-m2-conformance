#!/usr/bin/env bash
# Prepares the polkajam node-under-test binary.
#
# The workspace depends on polkajam's library crates as ordinary git
# dependencies (see the root Cargo.toml). This script is only needed to obtain
# the `polkajam` *binary* used as the NUT, which requires two local patches
# that the library dependency does not:
#   - patches/polkajam-alpn-v1.patch      jamnp-s/0 -> jamnp-s/1 (net/mod.rs)
#   - patches/polkajam-generic-sandbox.patch  polkavm generic-sandbox feature,
#     needed where vm.unprivileged_userfaultfd=0 and no sudo is available
#
# The checkout lives in third_party/ which is gitignored: nothing from polkajam
# is committed to this repository.
set -euo pipefail
cd "$(dirname "$0")/.."

REPO=${POLKAJAM_REPO:-ssh://git@github.com/paritytech/polkajam.git}
REV=${POLKAJAM_REV:-44cc3ec20ea4bbfd75df6b56e3b7798eab1b15b2}
DEST=third_party/polkajam

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

for patch in patches/polkajam-alpn-v1.patch patches/polkajam-generic-sandbox.patch; do
    git -C "$DEST" apply "../../$patch"
    echo "applied $patch"
done

cargo build --release --manifest-path "$DEST/Cargo.toml" --bin polkajam

echo
echo "NUT binary: $DEST/target/release/polkajam"
echo "add it to PATH before a real-surface run:"
echo "  export PATH=\"\$PWD/$DEST/target/release:\$PATH\""
