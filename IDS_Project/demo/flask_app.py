"""Simple Flask UI to view alerts and simulate blocking an IP.

Endpoints:
- GET /alerts -> returns JSON list of alerts (reads demo/logs/alerts.txt)
- POST /block -> JSON body {"ip": "1.2.3.4"} will log a simulated block via firewall_action.block_ip
"""
from pathlib import Path
from flask import Flask, jsonify, request
from network_module.firewall_action import block_ip

APP = Flask(__name__)
ALERTS_PATH = Path(__file__).parent / 'logs' / 'alerts.txt'


def read_alerts():
    if not ALERTS_PATH.exists():
        return []
    lines = ALERTS_PATH.read_text(encoding='utf-8').strip().splitlines()
    # return last 200 alerts as simple strings
    return lines[-200:]


@APP.route('/alerts', methods=['GET'])
def alerts():
    return jsonify({'alerts': read_alerts()})


@APP.route('/block', methods=['POST'])
def block():
    data = request.get_json(force=True)
    ip = data.get('ip')
    if not ip:
        return jsonify({'error': 'missing ip in json body'}), 400
    log_path = Path(__file__).parent / 'logs' / 'firewall_actions.txt'
    ok = block_ip(ip, log_path)
    return jsonify({'blocked': ip, 'ok': bool(ok)})


if __name__ == '__main__':
    APP.run(host='127.0.0.1', port=5001, debug=True)
