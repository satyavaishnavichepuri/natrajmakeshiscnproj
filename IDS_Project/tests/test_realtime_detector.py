import joblib
import pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier

from network_module.realtime_detector import run_detection


def test_run_detection_logs(tmp_path):
    # create a tiny dataset
    df = pd.DataFrame({
        'src_ip': ['10.0.0.1', '10.0.0.2'],
        'window': [1, 1],
        'packet_count': [1, 100],
        'avg_pkt_size': [100, 200],
        'unique_dst': [1, 2],
        'TCP': [1, 50],
        'UDP': [0, 50],
        'packet_rate': [0.016, 1.66]
    })
    features_file = tmp_path / 'features.csv'
    features_file.write_text(df.to_csv(index=False))

    # train a simple model: label second row as anomaly
    X = df.drop(columns=['src_ip', 'window'])
    y = [0, 1]
    clf = RandomForestClassifier(n_estimators=10, random_state=1)
    clf.fit(X, y)
    model_file = tmp_path / 'model.pkl'
    joblib.dump(clf, model_file)

    alerts = tmp_path / 'alerts.txt'
    run_detection(model_file, features_file, alerts)
    content = alerts.read_text()
    assert 'Anomaly detected' in content or 'Anomaly' in content
