"""Demo runner: read pcap (or run sniff), extract features, load model and detect anomalies.

This script is intended for presentation/demo. It can run without root by using a pcap.
"""
import argparse
from pathlib import Path
import subprocess
import time


def run_demo(pcap: Path, model_path: Path):
    # 1. run sniffer in pcap mode to create raw CSV
    from network_module.packet_sniffer import pcap_to_csv
    from network_module.feature_extractor import compute_features, load_packets
    from network_module.realtime_detector import run_detection

    raw_csv = Path('data/raw/packets.csv')
    print('Converting pcap -> CSV')
    pcap_to_csv(pcap, raw_csv)
    print('Extracting features')
    df = load_packets(raw_csv)
    feats = compute_features(df)
    feats_path = Path('data/processed/features.csv')
    feats_path.parent.mkdir(parents=True, exist_ok=True)
    feats.to_csv(feats_path, index=False)
    print('Running detection')
    run_detection(model_path, feats_path, Path('demo/logs/alerts.txt'))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pcap', default='data/sample_capture.pcap')
    parser.add_argument('--model', default='ml_module/trained_model.pkl')
    args = parser.parse_args()
    pcap = Path(args.pcap)
    model = Path(args.model)
    if not pcap.exists():
        print(f'PCAP not found at {pcap}. Please provide a pcap or run live capture.')
        return
    if not model.exists():
        print(f'Model not found at {model}. Place trained_model.pkl in ml_module/ before running detection.')
        return
    run_demo(pcap, model)


if __name__ == '__main__':
    main()
