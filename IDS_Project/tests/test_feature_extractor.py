import pandas as pd
from pathlib import Path
import tempfile

from network_module.feature_extractor import compute_features


def test_compute_features_basic():
    data = [
        {'timestamp': '2025-10-29T00:00:00', 'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.2', 'protocol': 'TCP', 'length': 100},
        {'timestamp': '2025-10-29T00:00:10', 'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.3', 'protocol': 'UDP', 'length': 200},
        {'timestamp': '2025-10-29T00:01:05', 'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.4', 'protocol': 'TCP', 'length': 150},
    ]
    df = pd.DataFrame(data)
    feats = compute_features(df, window_seconds=60)
    # expect at least one row (aggregation per window)
    assert 'packet_count' in feats.columns
    assert 'avg_pkt_size' in feats.columns
    assert feats['packet_count'].sum() >= 1
