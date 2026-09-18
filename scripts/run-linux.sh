#!/usr/bin/env bash
# Build and run the GUI as the desktop user, granting only raw-packet access.
set -euo pipefail

if [[ "$(uname -s)" != Linux ]]; then
    echo "This launcher is for Linux only." >&2
    exit 1
fi
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd -- "$project_root"
cargo build --release --locked --target-dir "$project_root/target"
scanner_binary="$project_root/target/release/network-scanner"

capture_status=0
"$scanner_binary" --check-capture || capture_status=$?
if [[ "$capture_status" == 2 ]]; then
    setcap_binary="$(command -v setcap || true)"
    if [[ -z "$setcap_binary" ]]; then
        echo "Install the libcap tools (libcap2-bin on Debian/Ubuntu), then retry." >&2
        exit 1
    fi
    echo "Granting CAP_NET_RAW to $scanner_binary. The desktop app will run as your normal user."
    sudo -- "$setcap_binary" cap_net_raw=ep "$scanner_binary"
    "$scanner_binary" --check-capture
elif [[ "$capture_status" != 0 ]]; then
    exit "$capture_status"
fi
exec "$scanner_binary"
