"""Checks for the first SSH gateway install and old-updater transition."""

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class SSHGatewayInstall(unittest.TestCase):
    def test_installer_probes_real_ssh_route_before_claiming_success(self):
        source = (ROOT / "run.sh").read_text(encoding="utf-8")
        helper = (ROOT / "deploy/browser_ssh_probe.py").read_text(encoding="utf-8")
        probe = source.index('python3 -B -I "$blueprint_dir/deploy/browser_ssh_probe.py"')
        marker = source.index("if [[ ! -e $ssh_gateway_marker ]]; then", probe)
        self.assertLess(probe, marker)
        self.assertIn("http://127.0.0.1:8766/api/v1/browser-ssh/host-key", helper)
        self.assertIn('"Origin": "http://127.0.0.1:8766"', helper)
        self.assertIn('"host_key_blob"', helper)
        self.assertIn("hashlib.sha256(key).digest()", helper)
        self.assertIn('"${compose[@]}" stop ssh-gateway', source[probe:marker])
        self.assertIn("SOVAGRID_SSH_GATEWAY_SNAPSHOT:-0", source)
        self.assertIn("managed SSH gateway requires /opt/sovagrid-src", source)
        self.assertIn("# SOVAGRID_PUBLIC_SSH_REFRESH_V1", source)
        self.assertLess(source.index("public_web.py\" refresh"),
                        source.index("mv -Tf -- \"$gateway_marker_temp\" \"$ssh_gateway_marker\""))
        self.assertIn('SOVAGRID_PUBLIC_WEB_LOCK_HELD=1 python3 -B -I "$blueprint_dir/deploy/public_web.py" refresh', source)
        subprocess.run(["bash", "-n", str(ROOT / "run.sh")], check=True)

    def test_gateway_has_no_public_port_or_persistent_secret_store(self):
        source = (ROOT / "deploy/compose.yaml").read_text(encoding="utf-8")
        gateway = source.split("\n  ssh-gateway:\n", 1)[1].split("\nnetworks:\n", 1)[0]
        self.assertIn("read_only: true", gateway)
        self.assertIn("cap_drop: [ALL]", gateway)
        self.assertIn("networks: [private]", gateway)
        self.assertNotIn("ports:", gateway)
        self.assertNotIn("volumes:", gateway)


if __name__ == "__main__":
    unittest.main()
