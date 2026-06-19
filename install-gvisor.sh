#!/bin/bash
# Installs gVisor (runsc) and registers it as a rootless Podman runtime, enabling
# the `analyze.sh --hardened` flag (syscall-level isolation on top of the container).
# Run once, on the first day you want the hardened tier.
set -euo pipefail

ARCH="$(uname -m)"
case "$ARCH" in x86_64|aarch64) ;; *) echo "gVisor needs x86_64 or aarch64 (got $ARCH)"; exit 1 ;; esac

URL="https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cd "$TMP"

echo "[*] downloading runsc + shim (with sha512 verification)…"
for f in runsc containerd-shim-runsc-v1; do
    curl -fsSL -o "$f" "$URL/$f"
    curl -fsSL -o "$f.sha512" "$URL/$f.sha512"
done
sha512sum -c runsc.sha512 containerd-shim-runsc-v1.sha512 || { echo "checksum FAILED — aborting"; exit 1; }

echo "[*] installing to /usr/local/bin (needs sudo)…"
chmod a+rx runsc containerd-shim-runsc-v1
sudo mv runsc containerd-shim-runsc-v1 /usr/local/bin/

CONF="$HOME/.config/containers/containers.conf"
mkdir -p "$(dirname "$CONF")"
if ! grep -q 'runsc' "$CONF" 2>/dev/null; then
    echo "[*] registering runsc runtime in $CONF"
    { echo ""; echo "[engine.runtimes]"; echo 'runsc = ["/usr/local/bin/runsc"]'; } >> "$CONF"
fi

echo "[*] done. runsc version:"; runsc --version | head -1
echo
echo "Next: validate the hardened path actually filters egress under gVisor before trusting it:"
echo "  podman run --rm --runtime=runsc --cap-add=NET_ADMIN untrusted-analysis:latest \\"
echo "    bash -lc 'sudo /usr/local/bin/init-firewall.sh api.anthropic.com; \\"
echo "      (curl -s -m6 https://example.com >/dev/null && echo LEAK || echo BLOCK)'"
echo "Expect BLOCK. gVisor uses its own netstack, so confirm before relying on --hardened."
