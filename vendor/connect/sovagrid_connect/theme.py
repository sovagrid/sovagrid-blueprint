# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Small, local-only theme preference for the Connect launcher."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import tkinter as tk


CHOICES = {"Системная": "system", "Светлая": "light", "Тёмная": "dark"}
LABELS = {value: key for key, value in CHOICES.items()}

PALETTES = {
    "light": {"background": "#f5f7fb", "surface": "#ffffff", "foreground": "#1f2937",
              "border": "#cbd5e1", "hover": "#e2e8f0", "disabled": "#64748b",
              "selected": "#dbeafe"},
    "dark": {"background": "#111827", "surface": "#1f2937", "foreground": "#e5e7eb",
             "border": "#475569", "hover": "#334155", "disabled": "#94a3b8",
             "selected": "#334155"},
}


def preference_file() -> Path:
    if sys.platform == "darwin":
        root = Path.home() / "Library" / "Application Support" / "SovaGrid Connect"
    elif os.name == "nt":
        root = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming") / "SovaGrid Connect"
    else:
        configured = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
        root = (configured if configured.is_absolute() else Path.home() / ".config") / "sovagrid-connect"
    return root / "preferences.json"


def load_preference(path: Path | None = None) -> str:
    selected = path or preference_file()
    try:
        info = selected.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
            return "system"
        value = json.loads(selected.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return "system"
    return value.get("theme", "system") if isinstance(value, dict) and value.get("theme") in LABELS else "system"


def save_preference(theme: str, path: Path | None = None) -> bool:
    if theme not in LABELS:
        return False
    selected = path or preference_file()
    temporary: str | None = None
    try:
        selected.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, temporary = tempfile.mkstemp(prefix=".preferences-", dir=selected.parent)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            if hasattr(os, "fchmod"):
                os.fchmod(stream.fileno(), 0o600)
            json.dump({"theme": theme}, stream, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, selected)
        return True
    except OSError:
        return False
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


class ThemeManager:
    def __init__(self, root: tk.Tk) -> None:
        import tkinter as tk
        from tkinter import ttk

        self.tk = tk
        self.root = root
        self.style = ttk.Style(root)
        self.native = self.style.theme_use()
        self.system_background = root.cget("background")
        sample = tk.Text(root)
        self.system_text = {key: sample.cget(key) for key in
                            ("background", "foreground", "insertbackground", "selectbackground",
                             "selectforeground", "highlightbackground", "highlightcolor")}
        sample.destroy()
        self.current = load_preference()
        self.apply(self.current, persist=False)

    def style_text(self, widget: tk.Text) -> None:
        if self.current == "system":
            widget.configure(**self.system_text)
        else:
            colors = PALETTES[self.current]
            widget.configure(background=colors["surface"], foreground=colors["foreground"],
                             insertbackground=colors["foreground"], selectbackground=colors["selected"],
                             selectforeground=colors["foreground"], highlightbackground=colors["border"],
                             highlightcolor=colors["border"])

    def style_window(self, window: tk.Toplevel) -> None:
        window.configure(background=self.system_background if self.current == "system" else
                         PALETTES[self.current]["background"])

    def apply(self, selected: str, *, persist: bool = True) -> bool:
        if selected not in LABELS:
            return False
        self.current = selected
        if selected == "system":
            self.style.theme_use(self.native)
            self.root.configure(background=self.system_background)
        else:
            colors = PALETTES[selected]
            self.style.theme_use("clam")
            self.style.configure(".", background=colors["background"], foreground=colors["foreground"],
                                 fieldbackground=colors["surface"], bordercolor=colors["border"])
            for name in ("TFrame", "TLabel", "TLabelframe", "TLabelframe.Label", "TCheckbutton"):
                self.style.configure(name, background=colors["background"], foreground=colors["foreground"])
            self.style.configure("TButton", background=colors["surface"], foreground=colors["foreground"],
                                 bordercolor=colors["border"], padding=5)
            self.style.map("TButton", background=[("active", colors["hover"]),
                                                   ("pressed", colors["selected"])],
                           foreground=[("disabled", colors["disabled"])])
            for name in ("TEntry", "TCombobox"):
                self.style.configure(name, fieldbackground=colors["surface"],
                                     foreground=colors["foreground"], bordercolor=colors["border"])
                self.style.map(name, fieldbackground=[("readonly", colors["surface"]),
                                                      ("disabled", colors["background"])],
                               foreground=[("readonly", colors["foreground"]),
                                           ("disabled", colors["disabled"])])
            self.style.map("TCheckbutton", background=[("active", colors["background"])],
                           foreground=[("disabled", colors["disabled"])])
            self.root.configure(background=colors["background"])
        self._refresh_children(self.root)
        return save_preference(selected) if persist else True

    def _refresh_children(self, parent: tk.Misc) -> None:
        for child in parent.winfo_children():
            if isinstance(child, self.tk.Toplevel):
                self.style_window(child)
            elif isinstance(child, self.tk.Text):
                self.style_text(child)
            self._refresh_children(child)
