# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Open the SovaGrid web panel through a local OpenSSH tunnel."""

from .core import ConnectionOptions, Tunnel, TunnelError

__version__ = "0.7.0"

__all__ = ["ConnectionOptions", "Tunnel", "TunnelError"]
