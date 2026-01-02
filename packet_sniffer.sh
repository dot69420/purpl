#!/bin/bash

# Packet Sniffer Automation
# Usage: sudo ./packet_sniffer.sh <INTERFACE>

INTERFACE=$1
DATE=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="scans/packets/$DATE"

if [ -z "$INTERFACE" ]; then
    echo "Usage: sudo $0 <INTERFACE>"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root."
    exit 1
fi

# Check for tcpdump
if ! command -v tcpdump &> /dev/null; then
    echo "[-] tcpdump could not be found. Please install it."
    echo "    Arch: sudo pacman -S tcpdump"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/capture.pcap"

echo "[+] Starting Packet Capture on $INTERFACE"
echo "[+] Saving to $OUTPUT_FILE"
echo "[+] Press Ctrl+C to stop..."

# Run tcpdump
# -i: Interface
# -w: Write to file
# -v: Verbose (print count)
tcpdump -i "$INTERFACE" -w "$OUTPUT_FILE" -v

echo -e "\n[+] Capture saved to $OUTPUT_FILE"
