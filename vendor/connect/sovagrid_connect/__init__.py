# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Jigokuraku01
"""Open the SovaGrid web panel through a local OpenSSH tunnel."""

from .core import ConnectionOptions, Tunnel, TunnelError

__version__ = "1.0.0"

__all__ = ["ConnectionOptions", "Tunnel", "TunnelError"]
