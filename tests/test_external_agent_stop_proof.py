# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Exact systemd/cgroup proof used by a future external Agent writer."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "external_agent_update.py"
spec = importlib.util.spec_from_file_location("sovagrid_external_stop_test", SCRIPT)
assert spec and spec.loader
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


class StopProofTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pid = 4242
        self.cgroup = "/system.slice/sovagrid-agent.service"
        self.state = "active"
        self.substate = "running"
        self.mainpid = str(self.pid)
        self.fragment = worker.AGENT_UNIT_FILE
        self.cgroup_property = self.cgroup
        self.controllers = self.root / "sys/fs/cgroup/cgroup.controllers"
        self.controllers.parent.mkdir(parents=True)
        self.controllers.write_text("cpu memory\n")
        self.unit_group = self.root / "sys/fs/cgroup" / self.cgroup.lstrip("/")
        self.unit_group.mkdir(parents=True)
        (self.unit_group / "cgroup.procs").write_text(str(self.pid) + "\n")
        process = self.root / "proc" / str(self.pid)
        process.mkdir(parents=True)
        self.stat = process / "stat"
        self.stat.write_text(self.proc_stat(12345))
        (process / "cgroup").write_text(f"0::{self.cgroup}\n")

    def proc_stat(self, ticks: int) -> str:
        # Field 22 (index 19 after the command name) is starttime.
        return f"{self.pid} (sovagrid agent) " + " ".join(
            ["S", *(["0"] * 18), str(ticks), "0"]) + "\n"

    def systemctl(self, command, **kwargs):
        self.assertEqual(command[:3],
                         ["/usr/bin/systemctl", "show",
                          "sovagrid-agent.service"])
        self.assertEqual(kwargs["timeout"], 5)
        fields = {
            "Id": "sovagrid-agent.service", "ActiveState": self.state,
            "SubState": self.substate, "MainPID": self.mainpid,
            "ControlGroup": self.cgroup_property,
            "InvocationID": "a" * 32, "FragmentPath": self.fragment,
            "NeedDaemonReload": "no",
        }
        output = "".join(f"{key}={value}\n" for key, value in fields.items())
        return subprocess.CompletedProcess(command, 0, output.encode(), b"")

    def proof(self) -> worker.ExternalAgentStopProof:
        return worker.ExternalAgentStopProof(run=self.systemctl, root=self.root,
                                             owner=os.geteuid())

    def stop(self) -> None:
        self.state = "inactive"
        self.substate = "dead"
        self.mainpid = "0"
        self.cgroup_property = ""
        self.stat.unlink()
        (self.unit_group / "cgroup.procs").write_text("")

    def test_stopped_requires_dead_unit_old_pid_gone_and_empty_cgroup(self):
        proof = self.proof()
        self.assertFalse(proof.stopped())
        self.stop()
        self.assertTrue(proof.stopped())

    def test_delegated_child_process_blocks_source_switch(self):
        proof = self.proof()
        self.stop()
        child = self.unit_group / "worker"
        child.mkdir()
        (child / "cgroup.procs").write_text("5222\n")
        self.assertFalse(proof.stopped())

    def test_old_process_escaping_cgroup_still_blocks_switch(self):
        proof = self.proof()
        self.stop()
        self.stat.write_text(self.proc_stat(12345))
        self.assertFalse(proof.stopped())

    def test_reused_pid_does_not_impersonate_old_agent(self):
        proof = self.proof()
        self.stop()
        self.stat.write_text(self.proc_stat(12346))
        self.assertTrue(proof.stopped())

    def test_restart_between_unit_and_cgroup_reads_blocks_switch(self):
        proof = self.proof()
        self.stop()
        calls = [0]

        def restarted(command, **kwargs):
            result = self.systemctl(command, **kwargs)
            calls[0] += 1
            if calls[0] == 1:
                self.state = "active"
                self.substate = "running"
                self.mainpid = "5333"
                self.cgroup_property = self.cgroup
            return result

        proof.run = restarted
        self.assertFalse(proof.stopped())
        self.assertEqual(calls[0], 2)

    def test_changed_unit_or_symlinked_cgroup_fails_closed(self):
        self.fragment = "/usr/lib/systemd/system/sovagrid-agent.service"
        with self.assertRaisesRegex(worker.Refused, "EXTERNAL_UNIT_INVALID"):
            self.proof()
        self.fragment = worker.AGENT_UNIT_FILE
        proof = self.proof()
        self.stop()
        child = self.unit_group / "outside"
        child.symlink_to(self.root)
        with self.assertRaisesRegex(worker.Refused, "EXTERNAL_CGROUP_INVALID"):
            proof.stopped()


if __name__ == "__main__":
    unittest.main()
