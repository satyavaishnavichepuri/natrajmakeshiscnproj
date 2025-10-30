# IDS_Project — Explanation and Runbook (from C:\Users\madha)

This document explains the project scope, exact commands to run the demo, problems we encountered and how they were fixed, and a detailed chain view showing how files call each other at runtime (imports, function calls and where they live). It also contains a short overview of the computer networks and ML theory used by this IDS.

All paths below are given from: `C:\Users\madha` (so the project root is `C:\Users\madha\natrajmakeshiscnproj\IDS_Project`).

## Scope

- Purpose: a hybrid computer-networks + ML anomaly-based IDS that can sniff or read pcap files locally, extract simple features, and run a trained ML model for anomaly detection in (near) real-time. The ML training is intended to run separately (e.g., in Google Colab) and the trained model is exported to `ml_module/trained_model.pkl`.
- Not destructive: firewall actions are simulated (logged) rather than changing system firewalls.
- Demo-friendly: contains pcap-to-CSV conversion, feature extraction, a toy RandomForest model for testing, a demo runner, a small Flask UI, and unit tests + CI.

## Quick commands (PowerShell, from project root)

Open PowerShell, change to the project root and create/activate a virtualenv. If PowerShell script execution is blocked, see the alternatives below.

```powershell
cd C:\Users\madha\natrajmakeshiscnproj\IDS_Project
python -m venv .venv
# Allow activation for this session only (temporary) if ExecutionPolicy blocks scripts
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
.\.venv\Scripts\Activate.ps1
```

Install runtime deps (lightweight option):

```powershell
pip install pandas numpy scikit-learn joblib flask pytest
# If you want live sniffing with scapy, also install scapy (may need OS packages):
pip install scapy
```

Run the demo (pcap -> features -> detection). Replace the pcap path with a real pcap if `data/sample_capture.pcap` is empty:

```powershell
python demo\demo_run.py --pcap data\sample_capture.pcap --model ml_module\trained_model.pkl
```

If you already have `data/processed/features.csv` and want to run detection directly:

```powershell
python -m network_module.realtime_detector --model ml_module\trained_model.pkl --features data\processed\features.csv --alerts demo\logs\alerts.txt
```

Start the Flask UI (to view alerts and simulate blocking):

```powershell
python demo\flask_app.py
# then open http://127.0.0.1:5001/alerts in a browser
```

Run unit tests (pytest):

```powershell
pytest -q
```

Notes on activation problems
- If PowerShell blocks `Activate.ps1` because of ExecutionPolicy, use `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force` temporarily (as shown above) or activate using the `activate.bat` script from `cmd.exe`.

## Problems we encountered and fixes (concise)

1. Requirement file mistake: `requirements.txt` contained `python>=3.10` which `pip` treats as a package and failed. Fix: removed that line — requirements now list only installable packages.
2. Relative import error: running `network_module/realtime_detector.py` as a script produced "attempted relative import with no known parent package". Fix: changed `from .utils import ...` to absolute `from network_module.utils import ...` and added `network_module/__init__.py` so the package can be imported when running from project root.
3. ModuleNotFoundError: `ModuleNotFoundError: No module named 'network_module'` occurred when running scripts from wrong CWD or before adding `__init__.py`. Fix: run commands from project root and that `__init__.py` present.
4. PowerShell script execution policy blocked venv activation. Fix: use `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force` or use `activate.bat` from cmd.exe.
5. Missing pcap: `demo_run.py` checks for `data/sample_capture.pcap` and will exit if it doesn't exist — replace with a real pcap or run `packet_sniffer.py` to capture live traffic (requires admin).
6. Native dependencies: `scapy` and pcap libraries may need OS-level dependencies (WinPCap/Npcap on Windows). For demo, use prepared CSVs and the toy model to avoid platform issues.

## File-by-file purpose (short)

- `README.md` — project overview and run instructions.
- `requirements.txt` — Python packages to install.
- `data/sample_capture.pcap` — placeholder pcap; replace with real capture.
- `data/raw/` — output of pcap conversion or live sniffer CSVs (packets.csv).
- `data/processed/features.csv` — output of `feature_extractor.py` used by the ML detector.
- `network_module/packet_sniffer.py` — uses scapy to sniff or read pcap and write packet metadata CSV.
- `network_module/feature_extractor.py` — reads raw packet CSV and computes derived features per `src_ip` per time window.
- `network_module/realtime_detector.py` — loads trained model and classifies feature rows; logs anomalies.
- `network_module/firewall_action.py` — simulates blocking an IP by writing a log entry.
- `network_module/utils.py` — helper functions: logger and model loader.
- `network_module/__init__.py` — package init (allows `import network_module...`).
- `ml_module/` — notebooks for preprocessing, training, evaluation, and a placeholder `trained_model.pkl`.
- `demo/demo_run.py` — orchestration script that converts pcap to CSV, extracts features, and runs detection.
- `demo/flask_app.py` — tiny Flask UI to view alerts (reads `demo/logs/alerts.txt`) and simulate blocking.
- `demo/logs/alerts.txt` — alerts log written by detector (example output recorded during smoke run).
- `tests/` — pytest unit tests for feature extraction and realtime detector.

## Detailed chain of execution (step-by-step, with exact code locations)

Below is a chain-style walk-through showing which file is executed first, which imports it performs, and which subsequent file/function is invoked. Paths and import lines are shown as they appear in the source.

1) Entry point for full demo: `demo\demo_run.py` (run from project root)

   - Command: `python demo\demo_run.py --pcap data\sample_capture.pcap --model ml_module\trained_model.pkl`
   - Inside `demo_run.py`, the `main()` function parses args and checks for pcap and model. If both exist, it calls `run_demo(pcap, model)`.
   - In `run_demo` the script performs these imports (these exact lines are in `demo/demo_run.py`):

     ```python
     from network_module.packet_sniffer import pcap_to_csv
     from network_module.feature_extractor import compute_features, load_packets
     from network_module.realtime_detector import run_detection
     ```

   - `demo_run.py` then calls `pcap_to_csv(pcap, raw_csv)` (from `network_module/packet_sniffer.py`) which uses scapy's `rdpcap()` to read the pcap and convert each packet via `pkt_to_dict()` into rows written to `data/raw/packets.csv`.

2) `network_module/packet_sniffer.py` (called by demo_run)

   - Key function called: `pcap_to_csv(pcap_path: Path, output_csv: Path)`
   - Implementation details (excerpt): it calls `packets = rdpcap(str(pcap_path))`, then builds `rows = [pkt_to_dict(pkt) for pkt in packets]` and finally `pd.DataFrame.from_records(rows).to_csv(output_csv, index=False)`.
   - `pkt_to_dict(pkt)` extracts fields from `pkt` using Scapy layers (`IP`, `TCP`, `UDP`) and returns a dict with keys: `timestamp, src_ip, dst_ip, protocol, length, src_port, dst_port`.

3) Back in `demo_run.py`: after pcap conversion, `demo_run` does `df = load_packets(raw_csv)` then `feats = compute_features(df)`.

4) `network_module/feature_extractor.py` (called by demo_run)

   - `load_packets(csv_path)` reads `data/raw/packets.csv` via `pd.read_csv(..., parse_dates=['timestamp'])`.
   - `compute_features(df, window_seconds=60)` does:
     - `df['ts'] = pd.to_datetime(df['timestamp'])`
     - `df['window'] = (df['ts'].astype('int64') // 10**9) // window_seconds * window_seconds` — this rounds timestamps down to discrete windows (e.g., per minute).
     - Groups by `['src_ip', 'window']` and aggregates: `packet_count`, `avg_pkt_size`, `unique_dst`.
     - Creates protocol counts via `pivot_table(index=['src_ip','window'], columns='protocol', values='timestamp', aggfunc='count')` (columns like `TCP`, `UDP` appear).
     - Merges and computes `packet_rate = packet_count / window_seconds`.
   - The consolidated `features` DataFrame is then saved to `data/processed/features.csv` (by `demo_run.py` or directly by feature_extractor's `main()` when run standalone).

5) `network_module/realtime_detector.py` (called by demo_run or can be run directly)

   - `run_detection(model_path: Path, features_csv: Path, alert_log: Path)` does:
     - `model = load_model(model_path)` — calls `network_module.utils.load_model`.
     - `df = pd.read_csv(features_csv)` to read the features CSV.
     - `X = df.drop(columns=['src_ip', 'window'], errors='ignore')`
     - `preds = model.predict(X)` — classifier outputs `0` (normal) or `1` (anomaly) by assumption.
     - For each anomaly row, `logger.warning(...)` writes a human-readable alert line to the alerts log (via `setup_logger` in `network_module.utils`). The printed message in `realtime_detector.py` confirms how many anomalies were logged.

   - Exact import line in `realtime_detector.py` (top of file):

     ```python
     from network_module.utils import load_model, setup_logger
     ```

6) `network_module/utils.py` (used by realtime_detector and firewall_action)

   - `load_model(path)` uses `joblib.load(path)` to load the trained model. If it fails, it raises a `RuntimeError` with the original exception.
   - `setup_logger(log_path, name='ids')` constructs a `logging.FileHandler` that writes alerts to `demo/logs/alerts.txt` (or the path you supply).

7) `network_module/firewall_action.py`

   - `block_ip(ip, log_path)` uses `setup_logger` to write a simulated block action to `log_path`. The module contains a small demo in `if __name__ == '__main__':` that demonstrates writing to `demo/logs/firewall_actions.txt`.

8) Flask UI: `demo/flask_app.py`

   - On GET `/alerts`: `read_alerts()` reads `demo/logs/alerts.txt` and returns the last 200 lines as JSON.
   - On POST `/block` with `{"ip":"x.x.x.x"}`: calls `network_module.firewall_action.block_ip(ip, log_path)` to simulate blocking and logs it.

## Computer networks theory (brief, as applied here)

- Packet capture: each network packet contains headers (Ethernet, IP, TCP/UDP) plus payload. Scapy exposes these layers; the sniffer extracts fields: `src_ip`, `dst_ip`, `protocol`, `length`, `src_port`, `dst_port`, and `timestamp`.
- Windowing & aggregation: security analytics often aggregate packet-level events into time windows (e.g., per-minute per-source IP) to compute rates and distributions. This reduces noise and provides features that represent behavior over time.
- Features used (examples):
  - `packet_count`: total packets in a window (proxy for volume).
  - `packet_rate`: normalized rate (packets/second).
  - `avg_pkt_size`: average payload/header length — can distinguish small-packet floods vs large transfers.
  - `protocol` counts (TCP vs UDP): distribution of protocols used.
  - `unique_dst`: number of distinct destination IPs reached by a source (useful to detect scanning behavior).
- Detection use-cases: DoS/DDoS (very high volume), port scans (many unique destinations or ports), exfiltration (sustained large average packet sizes), reflection/amplification patterns, anomalous protocol mixes.

## Machine learning theory (brief, as applied here)

- Supervised anomaly detection: we treat the problem as a binary classification (0 = normal, 1 = anomaly). A model such as RandomForest is trained on labeled examples (features as above) and used to predict anomalies on new windows.
- RandomForest basics: ensemble of decision trees, reduces variance via bagging, handles mixed numeric/categorical features well, robust to scaling but not immune to concept drift.
- Preprocessing: categorical encoding (if needed), scaling for some algorithms (SVM). Important: the same preprocessing pipeline used in training must be applied at runtime. Recommended: use an `sklearn.pipeline.Pipeline` that includes preprocessing + classifier and joblib.dump the whole pipeline.
- Metrics: because anomalies are rare, prefer precision/recall and ROC/AUC over plain accuracy. Confusion matrix is essential to understand false positives (FP) vs false negatives (FN). In IDS, FN (missed attacks) are often more critical than FP, but FP overwhelm analysts.
- Operational concerns: model drift, labeling quality, class imbalance, feature drift (if the format of packets changes), latency requirements for real-time detection.

## Recommended slide/demo talking points (copy-paste)

1. "We read raw packets (pcap or live), extract simple network-level features per-source per-time-window, and run a trained RandomForest to label windows as normal/anomalous. Alerts are logged and a small Flask endpoint shows recent alerts."
2. Show `data/processed/features.csv` columns and example rows (use the sample printed in your run) and explain each column's meaning.
3. Show `demo/logs/alerts.txt` lines (these are real log lines generated by the demo run). Explain why the logged rows looked suspicious (high packet_count, many unique destinations, etc.).
4. Point out limitations: toy model, synthetic labels, need for robust preprocessing pipeline in production, and permission/OS constraints around live sniffing.

## Extra troubleshooting notes

- If you see `ModuleNotFoundError: No module named 'network_module'`:
  - Make sure you run commands from the project root and that `network_module/__init__.py` exists.
  - Alternatively run detection as a module: `python -m network_module.realtime_detector ...` from project root.
- If `scapy` import fails or requires native libs: skip live sniffing and use pcap-to-csv conversion on a machine with scapy installed or run on Linux/VM with pcap libraries.
- When replacing the toy model with a Colab-trained model, save the full sklearn Pipeline (preprocessing + classifier) with `joblib.dump(pipeline, 'trained_model.pkl')` and place it at `ml_module/trained_model.pkl`.

## Final notes

This document was generated from the project workspace at `C:\Users\madha\natrajmakeshiscnproj\IDS_Project`. If you want, I can also generate a short one-page slide (Markdown or HTML) that contains the key commands, the feature table snapshot and the alerts sample for your presentation. Tell me which format you prefer.
