"""
Convert pcap to flow-level features (5-tuple aggregation).
Usage:
    python flow_extract.py --pcap capture.pcap --out flows.csv --timeout 60
Note: For larger pcap files, use pyshark/tshark for performance.
"""
import argparse
from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
import numpy as np

def tuple_key(pkt):
    """
    Return normalized 5-tuple (src, dst, sport, dport, proto) in direction-agnostic order.
    Ports are swapped to match the address ordering so reverse-direction packets map to same key.
    """
    ip = pkt.getlayer(IP)
    if ip is None:
        return None
    proto = None
    sport = 0
    dport = 0
    if pkt.haslayer(TCP):
        proto = 6
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)
    elif pkt.haslayer(UDP):
        proto = 17
        sport = int(pkt[UDP].sport)
        dport = int(pkt[UDP].dport)
    else:
        proto = int(ip.proto or 0)
    a1, a2 = ip.src, ip.dst
    if a1 < a2:
        return (a1, a2, sport, dport, proto)
    else:
        # swap ports for consistent ordering
        return (a2, a1, dport, sport, proto)

def extract_flows(pcap_file, out_csv=None, flow_timeout=60):
    packets = rdpcap(pcap_file)
    flows = {}
    for pkt in packets:
        try:
            ip = pkt.getlayer(IP)
            if ip is None:
                continue
            k = tuple_key(pkt)
            if k is None:
                continue
            ts = float(pkt.time)
            size = len(pkt)
            if k not in flows:
                flows[k] = {
                    "start": ts,
                    "end": ts,
                    "pkt_count": 0,
                    "byte_count": 0,
                    "sizes": [],
                    "flags": [],
                }
            f = flows[k]
            f["end"] = max(f["end"], ts)
            f["pkt_count"] += 1
            f["byte_count"] += size
            f["sizes"].append(size)
            # TCP flags
            if pkt.haslayer(TCP):
                try:
                    f["flags"].append(pkt[TCP].flags)
                except Exception:
                    pass
        except Exception:
            # be resilient to weird packets
            continue

    rows = []
    for k, v in flows.items():
        src, dst, sport, dport, proto = k
        duration = max(0.000001, v["end"] - v["start"])
        mean_pkt = float(np.mean(v["sizes"])) if v["sizes"] else 0.0
        std_pkt = float(np.std(v["sizes"])) if v["sizes"] else 0.0
        syn_count = fin_count = ack_count = 0
        try:
            for fl in v["flags"]:
                s = str(fl)
                if 'S' in s: syn_count += 1
                if 'F' in s: fin_count += 1
                if 'A' in s: ack_count += 1
        except Exception:
            pass
        row = {
            "src": src, "dst": dst, "sport": sport, "dport": dport, "proto": proto,
            "pkt_count": v["pkt_count"],
            "byte_count": v["byte_count"],
            "duration": duration,
            "bpk": v["byte_count"] / duration,
            "mean_pkt_size": mean_pkt,
            "std_pkt_size": std_pkt,
            "syn_count": syn_count,
            "fin_count": fin_count,
            "ack_count": ack_count,
            "start": v["start"],
            "end": v["end"]
        }
        rows.append(row)
    df = pd.DataFrame(rows)
    if df.empty:
        print("[!] No flows extracted.")
    else:
        # add some derived features
        df["pkt_per_sec"] = df["pkt_count"] / df["duration"]
        df["byte_per_pkt"] = df["byte_count"] / (df["pkt_count"].replace(0,1))
    if out_csv:
        df.to_csv(out_csv, index=False)
        print(f"[+] Wrote {len(df)} flows to {out_csv}")
    else:
        print(f"[+] Extracted {len(df)} flows (not written to CSV).")
    return df

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", required=True, help="Input pcap file")
    parser.add_argument("--out", default="flows.csv", help="Output CSV")
    parser.add_argument("--timeout", type=int, default=60, help="Flow timeout in seconds (not used in this simple extractor)")
    args = parser.parse_args()
    extract_flows(args.pcap, out_csv=args.out, flow_timeout=args.timeout)
