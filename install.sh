#!/usr/bin/env bash
set -euo pipefail

QUEUE="${1:-logia-zpl}"

if [[ $# -gt 1 ]]; then
    echo "Usage: sudo ./install.sh [queue-name]"
    exit 1
fi

if [[ ! "$QUEUE" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo "ERROR: Invalid printer queue name."
    exit 1
fi
BACKEND="/usr/lib/cups/backend/logiausb"
CONVERTER="/usr/local/libexec/logia-zpl-convert.py"
DRIVER="drv:///sample.drv/zebra.ppd"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $EUID -ne 0 ]]; then
    echo "Please run with sudo:"
    echo "  sudo ./install.sh"
    exit 1
fi

for command in lpadmin lpinfo lpstat; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "ERROR: Missing command: $command"
        echo "Install and enable CUPS first."
        exit 1
    fi
done

if [[ ! -x /usr/lib/cups/backend/usb ]]; then
    echo "ERROR: Standard CUPS USB backend not found."
    exit 1
fi

if ! lpinfo -m | grep -Fq "$DRIVER"; then
    echo "ERROR: Zebra ZPL driver is not available."
    exit 1
fi

if lpstat -p "$QUEUE" >/dev/null 2>&1; then
    echo "ERROR: Printer queue '$QUEUE' already exists."
    echo "Existing printer configuration has not been changed."
    echo "Remove or rename the queue manually before installing."
    exit 1
fi

echo "Installing Logia LOGLP300 driver..."

install -D -m 755 \
    "$SCRIPT_DIR/logia-zpl-convert.py" \
    "$CONVERTER"

install -D -m 744 \
    "$SCRIPT_DIR/logiausb" \
    "$BACKEND"

if command -v restorecon >/dev/null 2>&1; then
    restorecon -v "$BACKEND" "$CONVERTER"
fi

echo "Configuring CUPS printer queue..."

lpadmin -p "$QUEUE" \
    -E \
    -v "logiausb:/" \
    -m "$DRIVER"

echo
echo "Installation complete."
echo "Printer queue: $QUEUE"
echo
lpstat -v "$QUEUE"
