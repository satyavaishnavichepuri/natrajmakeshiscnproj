"""Read raw packet CSV and compute simple derived features for ML.

Produces a processed CSV with features per time window (e.g., per minute per src_ip).
"""
import pandas as pd
from pathlib import Path
from datetime import datetime
import argparse


def load_packets(csv_path: Path) -> pd.DataFrame:
    df = pd.read_csv(csv_path, parse_dates=['timestamp'])
    return df


def compute_features(df: pd.DataFrame, window_seconds: int = 60) -> pd.DataFrame:
    # Round timestamps to window
    df = df.dropna(subset=['timestamp'])
    df['ts'] = pd.to_datetime(df['timestamp'])
    df['window'] = (df['ts'].astype('int64') // 10**9) // window_seconds * window_seconds
    # aggregate per src_ip per window
    agg = df.groupby(['src_ip', 'window']).agg(
        packet_count=('timestamp', 'count'),
        avg_pkt_size=('length', 'mean'),
        unique_dst=('dst_ip', 'nunique')
    ).reset_index()

    # protocol counts
    prot = df.pivot_table(index=['src_ip', 'window'], columns='protocol', values='timestamp', aggfunc='count', fill_value=0)
    prot = prot.reset_index()

    features = agg.merge(prot, on=['src_ip', 'window'], how='left')
    # packet rate per second
    features['packet_rate'] = features['packet_count'] / window_seconds
    return features


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--in', dest='infile', default='data/raw/packets.csv')
    parser.add_argument('--out', default='data/processed/features.csv')
    parser.add_argument('--window', type=int, default=60)
    args = parser.parse_args()
    inp = Path(args.infile)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    df = load_packets(inp)
    feat = compute_features(df, window_seconds=args.window)
    feat.to_csv(out, index=False)
    print(f'Wrote features to {out}')


if __name__ == '__main__':
    main()
