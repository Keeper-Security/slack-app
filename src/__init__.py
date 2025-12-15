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
Keeper Slack App - Standalone Package

A Slack integration for Keeper Commander that allows users to 
request record/folder access, create one-time shares, and manage 
approvals directly from Slack.
"""

from .app import KeeperSlackApp

__all__ = ['KeeperSlackApp']
__version__ = '1.0.0'
