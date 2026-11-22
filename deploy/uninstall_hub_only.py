# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Jigokuraku01
"""Ownership boundaries for removing the Hub from a shared Agent host."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat

import hub_only_update as updates
import promote_agent_only as promotion
import remote_update_worker as installed


SYSTEMD = Path('/etc/systemd/system')
SHARED_CONFIG = Path('/etc/sovagrid')
SHARED_FILES = (
    'deploy.env', 'admin-password', '.vpn-unit-managed-by-run-sh',
    '.external-agent-recovery-managed-by-run-sh',
    '.external-agent-apply-managed-by-run-sh', 'release-feed.json',
)
LOCAL_WEB = SHARED_CONFIG / 'local-web'
PUBLIC_WEB = SHARED_CONFIG / 'public-web'
LOCAL_SERVICE = Path('/etc/sovagrid-service-local')
VPN_CONTROL = ('sovagrid-vpn-control.socket', 'sovagrid-vpn-control.service')
VPN_PROGRAMS = (Path('/usr/local/bin/sovagrid-vpn-ctl'),
                Path('/usr/local/libexec/sovagrid-vpn-broker'))
RECOVERY_LINK = SYSTEMD / 'sovagrid-agent.service.requires/sovagrid-external-agent-recovery.service'
PROMOTION_FILES = frozenset({
    promotion.BASELINE.name, promotion.PIN.name, promotion.LOCAL.name,
    promotion.LOCAL_OPERATIONS.name, 'local-container-inventory.json',
})
DEPENDENT_PENDING = (promotion.LOCAL_OPERATIONS_PENDING,
                     promotion.STATE_DIR / 'local-container-inventory-pending.json')


@dataclass(frozen=True)
class HubOnly:
    local_id: str | None
    allowed_units: frozenset[str]
    extra_paths: tuple[Path, ...]
    regular_paths: frozenset[Path]
    retained_paths: tuple[Path, ...]
    external: dict | None

    def recheck_external(self):
        if self.external is not None:
            promotion.need(self.external == promotion.capture_external(check_runtime=False),
                           'External Agent or SSH tunnel changed during removal')


def is_hub_only() -> bool:
    return any(os.path.lexists(name) for name in installed.HUB_ONLY_FOOTPRINTS)


def _check_hub_only_units(manifest):
    # The pair is written only by run.sh --hub-only, including a Hub installed
    # directly without an attached local Agent or a promotion journal.
    for name in ('sovagrid-hub-only-update.service', 'sovagrid-hub-only-update.timer'):
        raw = installed.public_path(str(SYSTEMD / name), limit=8192)
        expected = manifest['sha256'].get('sovagrid-blueprint/deploy/' + name)
        promotion.need(hashlib.sha256(raw).hexdigest() == expected,
                       'Hub-only unit differs from the installed manifest')


def _shared_configuration():
    files = []
    for name in SHARED_FILES:
        path = SHARED_CONFIG / name
        if not os.path.lexists(path):
            continue
        raw = installed.public_path(str(path), private=True, limit=8192)
        if name == 'deploy.env':
            promotion.need({b'SOVAGRID_HUB_DATA_DIR=/var/lib/sovagrid/hub',
                            b'SOVAGRID_CADDY_DATA_DIR=/var/lib/sovagrid/caddy'}
                           <= set(raw.splitlines()), 'Shared Compose configuration is not managed')
        elif name in ('.vpn-unit-managed-by-run-sh', '.external-agent-recovery-managed-by-run-sh'):
            promotion.need(raw == b'', 'Shared installation marker changed')
        elif name == 'release-feed.json':
            marker = '/var/lib/sovagrid/.release-feed-units-managed-by-run-sh'
            promotion.need(installed.public_path(marker, private=True) ==
                           b'SOVAGRID_RELEASE_FEED_UNITS_V1\n', 'Shared release feed is not managed')
        files.append(path)
    return files


def _web_directory(path, inspect_overlay):
    inspect_overlay()
    promotion.need({item.name for item in path.iterdir()} <= {'.managed', 'state.json', 'generations'},
                   'Web configuration directory contains unknown files')
    generations = path / 'generations'
    if os.path.lexists(generations):
        installed.public_path(str(generations), directory=True, private=True)
        for item in generations.iterdir():
            promotion.need(re.fullmatch(r'[0-9a-f]{32}', item.name) is not None,
                           'Web configuration directory contains an unknown generation')
            installed.public_path(str(item), directory=True, private=True)


def _local_features():
    directories = []
    if os.path.lexists(LOCAL_SERVICE):
        installed.public_path(str(LOCAL_SERVICE), directory=True, private=True)
        promotion.need({item.name for item in LOCAL_SERVICE.iterdir()} in
                       ({'units.json'}, {'units.json', 'enabled'}), 'Unknown local service policy')
        policy = json.loads(installed.public_path(str(LOCAL_SERVICE / 'units.json'), private=True))
        promotion.need(type(policy) is dict and set(policy) == {'version', 'units'} and
                       type(policy['version']) is int and policy['version'] == 1 and
                       type(policy['units']) is dict, 'Invalid local service policy')
        marker = LOCAL_SERVICE / 'enabled'
        if os.path.lexists(marker):
            promotion.need(installed.public_path(str(marker), private=True) == b'enabled\n',
                           'Unknown local service marker')
        directories.append(LOCAL_SERVICE)
    inventory = updates.local_inventory
    if os.path.lexists(inventory.DIRECTORY) or os.path.lexists(inventory.STATE):
        try:
            enabled = inventory._record(inventory.STATE)
            gid = promotion.grp.getgrnam(promotion.LOCAL_USER).gr_gid
            # Verify ownership and files without requiring a running or fresh
            # collector, as an uninstall may follow a failure.
            inventory._physical(enabled, gid)
        except (inventory.Refused, inventory.operations.Refused) as error:
            raise promotion.PromotionError('Local container inventory is not managed') from error
        if enabled:
            directories.append(inventory.DIRECTORY)
    return directories


def inspect(manifest, manifest_digest) -> HubOnly:
    promotion.need(not any(os.path.lexists(marker) for marker in (
        promotion.AGENT_MARKER, RECOVERY_LINK, *DEPENDENT_PENDING)),
        'Shared Agent ownership or an unfinished maintenance operation must be resolved')
    _check_hub_only_units(manifest)
    updates._external_apply_idle()
    installed.public_path(str(SHARED_CONFIG), directory=True)

    local_id = None
    extra = _shared_configuration()
    regular = set(extra)
    for path, validator in ((LOCAL_WEB, installed.local_web_overlay),
                            (PUBLIC_WEB, installed.public_web_overlay)):
        if os.path.lexists(path):
            _web_directory(path, validator)
            extra.append(path)
    retained = []
    external = None
    if os.path.lexists(promotion.STATE_DIR):
        installed.public_path(str(promotion.STATE_DIR), directory=True, private=True)
        promotion.need({item.name for item in promotion.STATE_DIR.iterdir()} <= PROMOTION_FILES,
                       'Promotion journal contains unknown or unfinished state')
        # The recorded baseline identifies a promotion, but the independent
        # Agent may legitimately have been upgraded since it was first saved.
        promotion._private_json(promotion.BASELINE)
        pinned = promotion._pin()
        promotion.need(pinned is None or pinned == manifest_digest,
                       'Promotion journal points to a different Hub bundle')
        external = promotion.capture_external(check_runtime=False)
        extra.append(promotion.STATE_DIR)
        if os.path.lexists(promotion.LOCAL):
            local_id = promotion._local_record(check_runtime=False)
            promotion.need({item.name for item in promotion.LOCAL_ETC.iterdir()} ==
                           {promotion.LOCAL_CONFIG.name, promotion.LOCAL_TOKEN.name,
                            promotion.LOCAL_CA.name}, 'Local Agent configuration is not managed')
            extra.extend((promotion.LOCAL_SOURCE, promotion.LOCAL_ETC, *_local_features()))
            retained.extend(path for path in (promotion.LOCAL_DATA, promotion.LOCAL_SHELL_HOME)
                            if os.path.lexists(path))
        else:
            promotion.need(not promotion._local_artifacts(),
                           'Local Agent activation is incomplete')
    else:
        promotion.need(not promotion._local_artifacts(),
                       'Local Agent has no promotion journal')

    # The external Agent normally uses the unqualified Agent and PTY units.
    # The updater inventory identifies only units owned by the local Hub.
    allowed_units = {Path(name).name for name in updates.SNAPSHOT if Path(name).parent == SYSTEMD}
    vpn_marker = SHARED_CONFIG / '.vpn-control-managed-by-run-sh'
    if os.path.lexists(vpn_marker):
        installed.public_path(str(vpn_marker), private=True)
        for program in VPN_PROGRAMS:
            raw = installed.public_path(str(program), limit=8192)
            expected = manifest['sha256'].get('sovagrid-vpn/deploy/' + program.name)
            promotion.need(hashlib.sha256(raw).hexdigest() == expected,
                           'Hub-only VPN control program differs from the installed manifest')
        extra.extend((vpn_marker, *VPN_PROGRAMS))
        regular.update((vpn_marker, *VPN_PROGRAMS))
        allowed_units.update(VPN_CONTROL)
    return HubOnly(local_id, frozenset(allowed_units), tuple(extra), frozenset(regular),
                   tuple(retained), external)
