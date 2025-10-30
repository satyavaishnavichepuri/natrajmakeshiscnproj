"""Packet sniffer using scapy that writes captured packet metadata to CSV periodically.

This module supports two modes:
- live sniffing (requires elevated privileges)
- offline reading from a pcap (demo mode)

The CSV contains: timestamp, src_ip, dst_ip, protocol, length, src_port, dst_port
"""
from scapy.all import sniff, rdpcap
from scapy.layers.inet import IP, TCP, UDP
import pandas as pd
from pathlib import Path
import argparse
import time
from datetime import datetime
from typing import Optional


def pkt_to_dict(pkt):
    ts = getattr(pkt, 'time', time.time())
    src_ip = pkt[IP].src if IP in pkt else None
    dst_ip = pkt[IP].dst if IP in pkt else None
    proto = None
    src_port = None
    dst_port = None
    if TCP in pkt:
        proto = 'TCP'
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif UDP in pkt:
        proto = 'UDP'
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
    elif IP in pkt:
        proto = pkt[IP].proto
    length = len(pkt)
    return {
        'timestamp': datetime.fromtimestamp(ts).isoformat(),
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'protocol': proto,
        'length': length,
        'src_port': src_port,
        'dst_port': dst_port
    }


def sniff_live(output_csv: Path, iface: Optional[str] = None, count: int = 0, timeout: Optional[int] = None):
    """Sniff live packets and append metadata to CSV. count=0 means continuous until killed."""
    records = []

    def _handle(pkt):
        records.append(pkt_to_dict(pkt))
        if len(records) >= 100:
            _flush(records, output_csv)

    sniff(iface=iface, prn=_handle, store=False, count=count, timeout=timeout)
    if records:
        _flush(records, output_csv)


def _flush(records, output_csv: Path):
    df = pd.DataFrame.from_records(records)
    header = not output_csv.exists()
    df.to_csv(output_csv, mode='a', header=header, index=False)
    records.clear()


def pcap_to_csv(pcap_path: Path, output_csv: Path):
    packets = rdpcap(str(pcap_path))
    rows = [pkt_to_dict(pkt) for pkt in packets]
    if rows:
        pd.DataFrame.from_records(rows).to_csv(output_csv, index=False)


def main():
    parser = argparse.ArgumentParser(description='Simple packet sniffer (live or pcap)')
    parser.add_argument('--pcap', help='Read from pcap file instead of live capture')
    parser.add_argument('--out', default='data/raw/packets.csv')
    parser.add_argument('--iface', help='Interface to sniff')
    parser.add_argument('--timeout', type=int, help='Time to sniff in seconds')
    args = parser.parse_args()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    if args.pcap:
        pcap_to_csv(Path(args.pcap), out)
        print(f'Wrote packets from {args.pcap} to {out}')
    else:
        print('Starting live sniffing (press Ctrl+C to stop)')
        try:
            sniff_live(out, iface=args.iface, timeout=args.timeout)
        except PermissionError:
            print('Permission denied: run as administrator/root for live sniffing.')


if __name__ == '__main__':
    main()
