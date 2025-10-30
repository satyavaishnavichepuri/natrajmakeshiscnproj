"""Load trained model and run real-time detection on features.
"""
from pathlib import Path
import argparse
import pandas as pd
from network_module.utils import load_model, setup_logger


def run_detection(model_path: Path, features_csv: Path, alert_log: Path):
    model = load_model(model_path)
    df = pd.read_csv(features_csv)
    logger = setup_logger(alert_log)
    X = df.drop(columns=['src_ip', 'window'], errors='ignore')
    preds = model.predict(X)
    # assume model returns 0 for normal, 1 for anomaly
    df['pred'] = preds
    anomalies = df[df['pred'] == 1]
    for _, row in anomalies.iterrows():
        logger.warning(f"Anomaly detected for src_ip={row.get('src_ip')} window={row.get('window')} details={row.to_dict()}")
    print(f"Detection complete. {len(anomalies)} anomalies logged to {alert_log}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--model', default='ml_module/trained_model.pkl')
    parser.add_argument('--features', default='data/processed/features.csv')
    parser.add_argument('--alerts', default='demo/logs/alerts.txt')
    args = parser.parse_args()
    run_detection(Path(args.model), Path(args.features), Path(args.alerts))


if __name__ == '__main__':
    main()
