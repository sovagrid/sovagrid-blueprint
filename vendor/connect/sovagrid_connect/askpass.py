# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Private OpenSSH askpass helper for the desktop GUI.

OpenSSH launches this program with a prompt and reads one answer from stdout.
Passwords never enter argv, the environment, SSH configuration, or our logs.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import shlex
import sys


_HELPER_NAME = "SovaGrid-Connect-Askpass"
_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{20,100}")
_HOST = re.compile(r"authenticity of host ['\"]([^'\"]{1,255})['\"]", re.IGNORECASE)
_AUTH_QUESTION = re.compile(
    r"\b(?:password|passphrase|verification code|security code|one[- ]time|"
    r"authenticator|otp|2fa|two[- ]factor|pin|пароль|код подтверждения|одноразовый код)\b",
    re.IGNORECASE,
)


def classify_prompt(prompt: str) -> str:
    """Unknown host prompts require a fingerprint; anything ambiguous is denied."""
    if "remote host identification has changed" in prompt.lower() or "host key verification failed" in prompt.lower():
        return "deny"
    if "authenticity of host" in prompt.lower() or "continue connecting (yes/no" in prompt.lower():
        if "continue connecting (yes/no" in prompt.lower() and _FINGERPRINT.search(prompt):
            return "host_key"
        return "deny"
    return "secret" if _AUTH_QUESTION.search(prompt) else "deny"


def _bundle_roots() -> list[Path]:
    if getattr(sys, "frozen", False):
        executable = Path(sys.executable).resolve()
        # The bundle packs askpass inside its GUI folder or macOS .app.
        if executable.parent.name == "MacOS" and executable.parent.parent.name == "Contents":
            return [executable.parent.parent / "Helpers"]
        return [executable.parent]
    return [Path(__file__).resolve().parents[1] / "dist" / "SovaGrid-Connect-GUI"]


def helper_path(private_directory: str) -> str:
    """Locate the bundled helper or create a source-mode POSIX launcher."""
    from .core import TunnelError

    executable = _HELPER_NAME + (".exe" if os.name == "nt" else "")
    for root in _bundle_roots():
        for candidate in (root / _HELPER_NAME / executable, root / executable):
            if candidate.is_file() and (os.name == "nt" or os.access(candidate, os.X_OK)):
                return str(candidate)
    if getattr(sys, "frozen", False) or os.name == "nt":
        raise TunnelError(
            "Графический SSH-запрос недоступен: внутри приложения отсутствует "
            "SovaGrid-Connect-Askpass. Распакуйте GUI целиком."
        )
    launcher = Path(private_directory) / "ssh-askpass"
    command = shlex.quote(sys.executable)
    descriptor = os.open(str(launcher), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
    with os.fdopen(descriptor, "w", encoding="utf-8") as script:
        script.write(f'#!/bin/sh\nexec {command} -m sovagrid_connect.askpass "$@"\n')
    return str(launcher)


def _ask_host_key(prompt: str) -> str | None:
    import tkinter as tk
    from tkinter import ttk

    fingerprint = _FINGERPRINT.search(prompt)
    if fingerprint is None:
        return None
    host = _HOST.search(prompt)
    root = tk.Tk()
    root.title("SovaGrid · Новый SSH-сервер")
    root.resizable(False, False)
    root.attributes("-topmost", True)
    confirmed = tk.BooleanVar(value=False)
    result: list[str | None] = [None]
    frame = ttk.Frame(root, padding=20)
    frame.grid(sticky="nsew")
    ttk.Label(frame, text="Проверьте ключ SSH-сервера", font=("TkDefaultFont", 14, "bold")).grid(
        row=0, column=0, columnspan=2, sticky="w", pady=(0, 12)
    )
    ttk.Label(frame, text=host.group(1) if host else "Новый SSH-сервер", wraplength=500).grid(
        row=1, column=0, columnspan=2, sticky="w"
    )
    ttk.Label(frame, text=fingerprint.group(0), font=("TkFixedFont", 11), wraplength=500).grid(
        row=2, column=0, columnspan=2, sticky="w", pady=(8, 12)
    )
    ttk.Label(
        frame,
        text="Сверьте SHA256-отпечаток с консолью провайдера или администратором сервера. "
             "При несовпадении отмените подключение.",
        wraplength=500,
    ).grid(row=3, column=0, columnspan=2, sticky="w", pady=(0, 12))
    ttk.Checkbutton(
        frame, text="Я сверил отпечаток по независимому источнику", variable=confirmed,
    ).grid(row=4, column=0, columnspan=2, sticky="w", pady=(0, 16))

    def accept() -> None:
        if confirmed.get():
            result[0] = "yes"
            root.destroy()

    ttk.Button(frame, text="Отмена", command=root.destroy).grid(row=5, column=0, sticky="w")
    agree = ttk.Button(frame, text="Доверять ключу", command=accept, state="disabled")
    agree.grid(row=5, column=1, sticky="e")
    confirmed.trace_add("write", lambda *_: agree.configure(state="normal" if confirmed.get() else "disabled"))
    root.protocol("WM_DELETE_WINDOW", root.destroy)
    root.mainloop()
    return result[0]


def _ask_secret(prompt: str) -> str | None:
    import tkinter as tk
    from tkinter import simpledialog

    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    try:
        key_generation = os.environ.get("SOVAGRID_KEYGEN") == "1"
        translated = ("Повторите парольную фразу нового SSH-ключа" if "same passphrase" in prompt.lower()
                      else "Введите парольную фразу нового SSH-ключа") if key_generation else prompt[:800]
        return simpledialog.askstring(
            "SovaGrid · Новый SSH-ключ" if key_generation else "SovaGrid · SSH-вход",
            translated or "Введите SSH-пароль или парольную фразу ключа",
            show="*",
            parent=root,
        )
    finally:
        root.destroy()


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args == ["--self-test"]:
        os.write(1, b"SovaGrid askpass pipe OK\n")
        return 0
    if len(args) != 1:
        return 1
    prompt = args[0]
    category = classify_prompt(prompt)
    if category == "deny":
        return 1
    try:
        answer = _ask_host_key(prompt) if category == "host_key" else _ask_secret(prompt)
    except Exception:
        # The prompt may contain server-provided text. Never print it to a log.
        return 1
    if answer is None:
        return 1
    if "\n" in answer or "\r" in answer:
        return 1
    os.write(1, answer.encode("utf-8") + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
