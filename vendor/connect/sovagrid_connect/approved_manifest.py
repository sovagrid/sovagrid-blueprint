# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Choose only an installed, reviewed server manifest before exact source proof.

The first SSH hash is a selector, not an authorization decision. Each caller's
existing source probe verifies the selected manifest and executable files
before it reads state or changes the server.
"""

from __future__ import annotations

import re

from .installer import InstallError


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_PATH = "/opt/sovagrid-src/sovagrid-bundle.json"
_REPLY = re.compile(rb"([0-9a-f]{64})  /opt/sovagrid-src/sovagrid-bundle\.json\n\Z")


class ApprovedManifestSet:
    def __init__(self, approved: str | tuple[str, ...] | None):
        if approved is None:
            values: tuple[str, ...] = ()
        elif type(approved) is str:
            values = (approved,)
        elif type(approved) is tuple:
            values = approved
        else:
            raise InstallError("Список проверенных серверных выпусков неверен")
        if (len(values) > 16 or
                any(type(value) is not str or _SHA.fullmatch(value) is None for value in values) or
                len(set(values)) != len(values)):
            raise InstallError("Список проверенных серверных выпусков неверен")
        self.values = values
        self.selected: str | None = None

    def resolve(self, transport) -> str | None:
        if not self.values:
            return None
        if len(self.values) == 1:
            return self.values[0]
        if self.selected is None:
            transport._verify_root_access()
            command = transport._privileged + "/usr/bin/sha256sum -- " + _PATH
            code, raw = transport._execute(command, timeout=45, limit=256)
            match = _REPLY.fullmatch(raw)
            if code != 0 or match is None:
                raise InstallError("Не удалось проверить выпуск сервера по SSH")
            value = match.group(1).decode("ascii")
            if value not in self.values:
                raise InstallError("Установленный серверный выпуск не входит в проверенный список")
            self.selected = value
        return self.selected


class ApprovedManifestMixin:
    @property
    def approved_manifest_sha256(self) -> str | None:
        return self._approved_manifests.resolve(self.transport)

    @approved_manifest_sha256.setter
    def approved_manifest_sha256(self, value: str | tuple[str, ...] | None) -> None:
        self._approved_manifests = ApprovedManifestSet(value)

    @property
    def manifest(self) -> str | None:
        return self.approved_manifest_sha256

    @manifest.setter
    def manifest(self, value: str | tuple[str, ...] | None) -> None:
        self.approved_manifest_sha256 = value
