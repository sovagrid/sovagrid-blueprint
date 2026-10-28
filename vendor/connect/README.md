<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 Jigokuraku01 -->

# Vendored Connect Python runtime

`sovagrid_connect/` is an exact, tracked subset of the Python package from
[`sovagrid-connect`](https://github.com/sovagrid/sovagrid-connect) at the commit
recorded in `SOURCE.json`. It contains the Ubuntu runtime import closure for
`AgentEnrollment`, `EnrollmentAPI` and `AgentRPC`: 13 Python files and the
upstream licence, attribution and notice. Desktop GUI modules and bundled
desktop third-party notices are deliberately omitted. The selected files are
copied byte-for-byte and retain their original SPDX headers.

The server-source archive already includes every tracked Blueprint file. This
copy therefore travels inside the Blueprint component of the existing five
component archive, with every file covered by the archive manifest. No code
is fetched from GitHub when an installed server imports the package. Vendoring
the package does not enable the Web Agent installer by itself.

To update the copy, check out the exact intended upstream commit in a local
Connect checkout, update `UPSTREAM_COMMIT` in `tools/sync_connect_vendor.py`,
and run from the Blueprint repository:

```sh
python3 tools/sync_connect_vendor.py sync --source ../sovagrid-connect
python3 tools/sync_connect_vendor.py check --source ../sovagrid-connect
python3 -m unittest tests.test_vendor_connect -v
```

`check` without `--source` verifies all local vendored bytes against the lock.
CI should additionally check against a separate checkout of the recorded
Connect commit; that comparison requires no network access at runtime. The
subset is intentionally Ubuntu-only: optional Windows key helpers and the
desktop SSH-grant helper are excluded and must not be called by the host
installer.
