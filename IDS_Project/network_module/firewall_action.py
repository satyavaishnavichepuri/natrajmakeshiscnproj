"""Simulate firewall action on anomaly detection. This module avoids changing system firewall and instead logs the action.
"""
from pathlib import Path
from .utils import setup_logger


def block_ip(ip: str, log_path: Path):
    logger = setup_logger(log_path, name='firewall')
    logger.info(f"Simulated block action for IP: {ip}")
    # In real deployment, you'd call OS firewall utilities with appropriate permissions.
    return True


if __name__ == '__main__':
    # quick demo
    block_ip('192.0.2.5', Path('demo/logs/firewall_actions.txt'))
