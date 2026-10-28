#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Exercise the real Agent/Blueprint trial watchdog on disposable Linux CI."""

from __future__ import annotations

import grp
import hashlib
import importlib.util
import os
from pathlib import Path
import pwd
import re
import select
import shutil
import subprocess
import time


SOURCE = Path("/opt/sovagrid-src")
TRIAL_DIR = Path("/run/sovagrid-external-agent-trial")
EXPECTED_SHA = re.compile(r"[0-9a-f]{64}\Z")
CHILD = """from sovagrid_agent.trial_gate import from_environment
from sovagrid_agent import __main__ as agent_main
from types import SimpleNamespace
from unittest import mock
import time
gate = from_environment()
assert gate is not None
gate.start()
# Exercise the actual Agent metrics cycle with the journal permission enabled
# on the host. Trial mode must disable it along with command delivery, or
# configured_units rejects the otherwise valid host configuration.
host = agent_main.load_config('/etc/sovagrid/agent.json')
host.update(allow_remote_commands=True, allow_systemd_journal=True,
            journal_units=['ssh.service'], allow_interactive_terminal=True,
            allow_file_manager=True)
client = mock.Mock()
with mock.patch.object(agent_main, 'load_config', return_value=host), \\
     mock.patch.object(agent_main, 'read_token', return_value='test-token'), \\
     mock.patch.object(agent_main, 'HubClient', return_value=client), \\
     mock.patch('sovagrid_agent.agent.collect', return_value={'cpu_percent': 0.0, 'details': {}}):
    agent_main._run(SimpleNamespace(config='/etc/sovagrid/agent.json', once=True), trial_mode=True)
client.push_metrics.assert_called_once()
client.next_job.assert_not_called()
print('AGENT_TRIAL_READY', flush=True)
time.sleep(15)
"""


def require(value: bool, message: str) -> None:
    if not value:
        raise RuntimeError(message)


def child_command(epoch: str) -> list[str]:
    runuser = shutil.which("runuser")
    require(runuser is not None, "runuser is unavailable")
    return [runuser, "-u", "sovagrid", "--", "/usr/bin/env",
            f"PYTHONPATH={SOURCE / 'sovagrid-agent'}",
            "SOVAGRID_EXTERNAL_TRIAL_GATE=1",
            f"SOVAGRID_EXTERNAL_TRIAL_EPOCH={epoch}",
            "/usr/bin/python3", "-c", CHILD]


def main() -> None:
    require(os.geteuid() == 0 and os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and
            os.environ.get("RUNNER_OS") == "Linux", "Disposable root Linux CI only")
    expected = os.environ.get("SOVAGRID_EXPECTED_MANIFEST", "")
    require(EXPECTED_SHA.fullmatch(expected) is not None and
            hashlib.sha256((SOURCE / "sovagrid-bundle.json").read_bytes()).hexdigest() == expected,
            "Installed source differs from the exact CI bundle")
    uid, gid = pwd.getpwnam("sovagrid").pw_uid, grp.getgrnam("sovagrid").gr_gid
    require(not TRIAL_DIR.exists() and not TRIAL_DIR.is_symlink(),
            "A trial directory already exists on the disposable host")
    runuser = shutil.which("runuser")
    require(runuser is not None, "runuser is unavailable")
    imported = subprocess.run(
        [runuser, "-u", "sovagrid", "--", "/usr/bin/env",
         f"PYTHONPATH={SOURCE / 'sovagrid-agent'}", "/usr/bin/python3", "-c",
         "from sovagrid_agent.trial_gate import ExternalTrialGate; print('TRIAL_CLIENT_IMPORT_OK')"],
        capture_output=True, timeout=8, check=False)
    require(imported.returncode == 0 and imported.stdout == b"TRIAL_CLIENT_IMPORT_OK\n",
            "Cannot import the pinned Agent trial client as its service user")
    spec = importlib.util.spec_from_file_location(
        "sovagrid_trial_integration", SOURCE / "sovagrid-blueprint/deploy/external_agent_update.py")
    assert spec and spec.loader
    planner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(planner)

    # A systemd ExecStart after a dead supervisor must fail before the Agent
    # creates HubClient. The child calls the same startup gate as __main__.
    absent = subprocess.run(child_command("0" * 32), capture_output=True,
                            timeout=8, check=False)
    require(absent.returncode != 0 and b"AGENT_TRIAL_READY" not in absent.stdout,
            "Agent started without a live trial supervisor")

    TRIAL_DIR.mkdir(mode=0o710)
    os.chown(TRIAL_DIR, 0, gid)
    TRIAL_DIR.chmod(0o710)
    flags = {"lease": True}
    server = planner.TrialWatchServer(
        "a" * 64, group=gid, agent_uid=uid,
        journal_current=lambda: "a" * 64,
        lease_active=lambda: flags["lease"],
        agent_idle_proven=lambda: True,
        agent_peer_allowed=lambda _pid, peer_uid, peer_gid:
            peer_uid == uid and peer_gid == gid,
        directory=TRIAL_DIR)
    child = None
    try:
        server.start()
        child = subprocess.Popen(child_command(server.epoch), stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert child.stdout is not None
        ready, _, _ = select.select([child.stdout], [], [], 7)
        require(bool(ready) and child.stdout.readline() == b"AGENT_TRIAL_READY\n",
                "Agent did not complete the live trial handshake")
        # The next heartbeat must detect lost authorization and terminate the
        # trial process; the server cannot revive this epoch afterward.
        flags["lease"] = False
        _stdout, _stderr = child.communicate(timeout=8)
        require(child.returncode == 70 and server.closed.is_set(),
                "Agent did not fail closed when the supervisor lost its lease")
        print("INTEGRATED_EXTERNAL_AGENT_TRIAL_GATE_VERIFIED", flush=True)
    finally:
        server.close()
        if child is not None and child.poll() is None:
            child.kill()
            child.communicate(timeout=3)
        TRIAL_DIR.rmdir()


if __name__ == "__main__":
    main()
