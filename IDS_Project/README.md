# IDS_Project — Anomaly-based Intrusion Detection (CN + ML hybrid)

This repository is a scaffold for an anomaly-based Intrusion Detection System (IDS) that combines computer networking packet capture with an ML-based detector trained separately (for example, in Google Colab).

Structure
```
IDS_Project/
├── README.md
├── requirements.txt
├── data/
│   ├── raw/
│   ├── processed/
│   └── sample_capture.pcap
├── network_module/
│   ├── packet_sniffer.py
│   ├── feature_extractor.py
│   ├── realtime_detector.py
│   ├── firewall_action.py
   └── utils.py
├── ml_module/
│   ├── preprocessing.ipynb
│   ├── train_model.ipynb
│   ├── model_evaluation.ipynb
│   └── trained_model.pkl
├── demo/
│   ├── demo_run.py
│   ├── logs/
│   └── screenshots/
└── report/
```

Quick start (network module locally)

1. Create a Python >=3.10 virtual environment and install dependencies:

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

2. To run a demo that reads `data/sample_capture.pcap` and runs detection (no root required):

```powershell
python demo\demo_run.py --pcap data\sample_capture.pcap
```

3. To use live sniffing (requires admin/root privileges):

```powershell
python network_module\packet_sniffer.py
```

ML workflow (use Google Colab)

- Open `ml_module/preprocessing.ipynb` in Colab. Load NSL-KDD or CICIDS2017 dataset, preprocess and save processed CSV to `data/processed/` (you can upload back to this repo or keep on Google Drive).
- Open `ml_module/train_model.ipynb` in Colab to train a model (RandomForest/SVM). Export the trained model as `trained_model.pkl` (joblib) and put it into `ml_module/` or `network_module/models/` before running real-time detection.

Notes & permissions

- Packet sniffing requires elevated privileges. Use the provided pcap demo if you cannot run sniffing locally.
- This scaffold intentionally simulates firewall actions instead of changing OS firewall settings.

TODO:
- implement unit tests for network parsing and feature extraction,
- add a small Flask UI to view alerts,
- create Colab-ready notebooks with executable cells and a sample training run.

