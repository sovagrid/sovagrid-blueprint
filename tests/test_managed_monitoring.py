# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Jigokuraku01

import json
from pathlib import Path
import time
from unittest import TestCase, mock

from deploy import managed_monitoring as monitoring


class ManagedMonitoringTests(TestCase):
    hub = monitoring.Hub("1" * 64, "sha256:" + "2" * 64, "3" * 64)
    fresh = monitoring.Collector("4" * 64, True)

    def review(self, *, enabled=False, revision=0, collector=None, token=None, state="absent"):
        return monitoring.Review(self.hub, enabled, revision, token, collector, state)

    def test_preview_has_no_secret_and_captures_hub_revision_and_collector(self):
        token_hash = "a" * 64
        initial = self.review(token=token_hash)
        self.assertNotIn(token_hash, json.dumps(initial.result()))
        self.assertNotEqual(initial.fingerprint, self.review(token=token_hash, revision=1).fingerprint)
        self.assertNotEqual(initial.fingerprint, self.review(token=token_hash, collector=self.fresh).fingerprint)
        with mock.patch.object(monitoring, "_review", return_value=initial):
            self.assertEqual(monitoring.execute("preview", {}, authorize=mock.Mock()), initial.result())

    def test_invalid_or_stale_review_cannot_pull_or_mutate(self):
        with mock.patch.object(monitoring, "_review", return_value=self.review()) as observe, \
                mock.patch.object(monitoring, "_install") as write:
            with self.assertRaisesRegex(monitoring.MonitoringError, "^INVALID_INPUT$"):
                monitoring.execute("apply", {"confirm": True, "image": "other"}, authorize=mock.Mock())
            observe.assert_not_called()
            with self.assertRaisesRegex(monitoring.MonitoringError, "^STALE_PREVIEW$"):
                monitoring.execute("apply", {"confirm": True, "expected_review_sha256": "b" * 64},
                                   authorize=mock.Mock())
            write.assert_not_called()

    def test_install_rechecks_authority_before_deployment_and_hub_cas(self):
        events = []
        token_hash = "a" * 64
        def cli(_hub, *args):
            events.append(args)
            return (False, 0) if args == ("status",) else (True, 1)
        with mock.patch.object(monitoring, "_running_hub", return_value=self.hub), \
                mock.patch.object(monitoring, "_hub_status", side_effect=cli), \
                mock.patch.object(monitoring, "_prepare_image", side_effect=lambda: events.append("image ready")), \
                mock.patch.object(monitoring, "_compose", side_effect=lambda _, *args, **kw: events.append(args)), \
                mock.patch.object(monitoring, "_create_state", return_value=token_hash) as new_state, \
                mock.patch.object(monitoring, "_collector", return_value=self.fresh), \
                mock.patch.object(monitoring, "_promtool", return_value="ready"), \
                mock.patch.object(monitoring, "_scraping", return_value=True):
            reply = monitoring._install(self.review(), lambda: events.append("authorized"))
        new_state.assert_called_once_with()
        self.assertEqual(reply["state"], "ready")
        self.assertEqual(events, [
            "authorized", "image ready", "authorized",
            ("status",), ("up", "-d", "--no-build", "--pull", "never", "prometheus"), "authorized",
            ("configure", "--expected-revision", "0", "--exporter-token-sha256", token_hash),
        ])

    def test_rebind_reuses_the_secret_and_never_configures_a_disabled_hub(self):
        active = self.review(enabled=True, revision=2, token="a" * 64, state="needs_reconcile")
        with mock.patch.object(monitoring.os.path, "lexists", return_value=True), \
                mock.patch.object(monitoring, "_review", side_effect=[self.review(), active]), \
                mock.patch.object(monitoring, "_install") as write:
            monitoring.rebind()
            write.assert_not_called()
            monitoring.rebind()
            self.assertIs(write.call_args.args[0], active)

    def test_stale_collector_is_recreated_even_when_its_hub_id_matches(self):
        stale = self.review(enabled=True, revision=1, collector=self.fresh,
                            token="a" * 64, state="needs_reconcile")
        ready = self.review(enabled=True, revision=1, collector=self.fresh,
                            token="a" * 64, state="ready")
        replacement = monitoring.Collector("5" * 64, True)
        with mock.patch.object(monitoring, "_running_hub", return_value=self.hub), \
                mock.patch.object(monitoring, "_hub_status", return_value=(True, 1)), \
                mock.patch.object(monitoring, "_prepare_image") as prepare, \
                mock.patch.object(monitoring, "_compose") as compose, \
                mock.patch.object(monitoring, "_create_state") as create_state, \
                mock.patch.object(monitoring, "_collector", return_value=replacement), \
                mock.patch.object(monitoring, "_wait"):
            self.assertEqual(monitoring._install(ready, mock.Mock())["state"], "ready")
            prepare.assert_not_called()
            compose.assert_not_called()
            self.assertEqual(monitoring._install(stale, mock.Mock())["state"], "ready")
            create_state.assert_not_called()
        compose.assert_called_once_with(self.hub, "up", "-d", "--no-build", "--pull", "never",
                                        "--force-recreate", "prometheus", timeout=32)

    def test_promtool_must_report_a_successful_scrape_from_this_operation(self):
        base = time.time() - 1
        def result(timestamp):
            return json.dumps([{"metric": {}, "value": [base, str(timestamp)]}])
        with mock.patch.object(monitoring, "_promtool", side_effect=[result(base - 1), result(base)]):
            self.assertFalse(monitoring._scraping(self.fresh, after=base))
            self.assertTrue(monitoring._scraping(self.fresh, after=base))

    def test_only_managed_loopback_collector_is_declared(self):
        compose = (Path(__file__).parents[1] / "deploy/compose.monitoring.yaml").read_text()
        self.assertIn("image: " + monitoring.IMAGE, compose)
        self.assertIn("--web.listen-address=127.0.0.1:9090", compose)
        self.assertNotIn("ports:", compose)
        self.assertNotIn("docker.sock", compose)
