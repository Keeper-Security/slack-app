# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""
Keeper Slack App - Entry Point

Run this script to start the Keeper Slack integration.
Make sure to configure slack_config.yaml before running.
"""


import warnings
warnings.filterwarnings("ignore", message=".*LibreSSL.*")
warnings.filterwarnings("ignore", message=".*NotOpenSSLWarning.*")

import os

from src.app import KeeperSlackApp
from src.logger import logger


def main():
    """Start the Keeper Slack App."""
    config_path = os.path.join(os.path.dirname(__file__), 'slack_config.yaml')
    
    print("=" * 60)
    print("Starting Keeper Slack App")
    print("=" * 60)
    logger.info(f"Config: {config_path}")
    print("=" * 60)
    
    app = KeeperSlackApp(config_path=config_path)
    app.start()


if __name__ == "__main__":
    main()
