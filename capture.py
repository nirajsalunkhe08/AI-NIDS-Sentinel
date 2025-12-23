"""
Simple packet capture to pcap file using scapy.
Usage:
    sudo python capture.py --iface eth0 --duration 60 --out sample.pcap
"""
import argparse
from scapy.all import sniff, wrpcap

def capture_iface(iface, duration, out):
    print(f"[+] Starting capture on {iface} for {duration}s -> {out}")
    packets = sniff(iface=iface, timeout=duration)
    print(f"[+] Captured {len(packets)} packets, saving...")
    wrpcap(out, packets)
    print("[+] Saved.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True, help="Network interface (e.g., eth0)")
    parser.add_argument("--duration", type=int, default=60, help="Seconds to capture")
    parser.add_argument("--out", default="capture.pcap", help="Output pcap filename")
    args = parser.parse_args()
    capture_iface(args.iface, args.duration, args.out)
