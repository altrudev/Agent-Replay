"""Hosted control plane for Agent Replay.

This package is intentionally separate from the standalone forensic core.
Billing, identity, quotas and account roles may control access, but they must
never alter forensic conclusions.
"""

__version__ = "0.1.0"
