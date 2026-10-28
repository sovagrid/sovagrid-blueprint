# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Future external Agent writer's original-Hub lease boundary."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "external_agent_update.py"
spec = importlib.util.spec_from_file_location("sovagrid_external_lease_test", SCRIPT)
assert spec and spec.loader
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


TOKEN = "a" * 43
EPOCH = "b" * 32
MANIFEST = "c" * 64


def reply(*, token: bool = True, expiry: int = 1_000_120,
          max_until: int = 1_000_900) -> dict:
    value = {"protocol": 1, "scope": "jobs_and_new_relays",
             "hub_epoch": EPOCH, "expires_at": expiry,
             "max_until": max_until, "agent_idle_proven": False}
    if token:
        value["lease_token"] = TOKEN
    return value


class LeaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = [20.0]
        self.calls: list[tuple[str, dict]] = []
        self.response = reply()

        def request(action: str, payload: dict) -> dict:
            self.calls.append((action, payload))
            if action == "acquire":
                return dict(self.response)
            if action == "renew":
                return reply(token=False, expiry=1_000_150)
            if action == "release":
                return {"released": True}
            raise AssertionError(action)

        self.request = request

    def lease(self) -> worker.OriginalHubLease:
        lease = worker.OriginalHubLease(
            {"identity": {"server_id": "unused by injected transport"}},
            MANIFEST, request=self.request, clock=lambda: self.now[0],
            renew_interval=30)
        self.addCleanup(lease.close)
        return lease

    def test_renewal_binds_epoch_token_and_original_bundle(self) -> None:
        lease = self.lease().acquire()
        self.assertTrue(lease.active())
        self.assertEqual(self.calls[0],
                         ("acquire", {"bundle_manifest_sha256": MANIFEST}))
        self.now[0] += 3
        lease.assert_held(fresh=True)
        self.assertEqual(self.calls[-1], ("renew", {"lease_token": TOKEN}))
        self.assertTrue(lease.active())
        lease.close()
        self.assertEqual(self.calls[-1], ("release", {"lease_token": TOKEN}))
        self.assertFalse(lease.active())

    def test_remote_utc_offset_does_not_determine_local_lifetime(self) -> None:
        lease = self.lease().acquire()
        # The Hub Unix time is intentionally unrelated to the remote Agent clock.
        self.now[0] = 899.0
        lease.assert_held(fresh=True)
        self.now[0] = 901.0
        with self.assertRaisesRegex(worker.Refused, "ORIGINAL_HUB_LEASE_EXPIRED"):
            lease.renew()
        self.assertFalse(lease.active())

    def test_invalid_acquire_response_cannot_start_a_lease(self) -> None:
        for change in ({"agent_idle_proven": True}, {"scope": "all"},
                       {"lease_token": "short"}, {"unexpected": 1},
                       {"expires_at": False}):
            with self.subTest(change=change):
                self.response = reply()
                self.response.update(change)
                lease = self.lease()
                with self.assertRaisesRegex(worker.Refused,
                                            "ORIGINAL_HUB_LEASE_INVALID"):
                    lease.acquire()
                self.assertFalse(lease.active())

    def test_lost_renewal_is_terminal_even_if_transport_recovers(self) -> None:
        lease = self.lease().acquire()
        good = self.request

        def fail(action: str, payload: dict) -> dict:
            if action == "renew":
                raise OSError("Hub process restarted")
            return good(action, payload)

        lease.request = fail
        with self.assertRaisesRegex(worker.Refused, "ORIGINAL_HUB_LEASE_LOST"):
            lease.assert_held(fresh=True)
        lease.request = good
        self.assertFalse(lease.active())
        with self.assertRaisesRegex(worker.Refused, "ORIGINAL_HUB_LEASE_LOST"):
            lease.renew()

    def test_changed_hub_epoch_refuses_renewal(self) -> None:
        lease = self.lease().acquire()

        def changed(action: str, payload: dict) -> dict:
            if action == "renew":
                return {**reply(token=False, expiry=1_000_150),
                        "hub_epoch": "d" * 32}
            return self.request(action, payload)

        lease.request = changed
        with self.assertRaisesRegex(worker.Refused, "ORIGINAL_HUB_LEASE_LOST"):
            lease.assert_held(fresh=True)
        self.assertFalse(lease.active())

    def test_renewer_start_failure_releases_acquired_token(self) -> None:
        lease = self.lease()
        with mock.patch.object(worker.threading.Thread, "start",
                               side_effect=RuntimeError("no threads")):
            with self.assertRaisesRegex(worker.Refused,
                                        "ORIGINAL_HUB_LEASE_UNAVAILABLE"):
                lease.acquire()
        self.assertEqual(self.calls[-1], ("release", {"lease_token": TOKEN}))
        self.assertFalse(lease.active())


if __name__ == "__main__":
    unittest.main()
