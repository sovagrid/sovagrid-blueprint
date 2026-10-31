# External Agent update and trial boundary

The Hub-only updater preserves the Agent originally enrolled with another
Hub. Updating that external Agent is a separate root operation. It is never
part of a Hub-only update, the signed full-server feed, or an automatic timer.
The source archive must already be staged by its SHA-256 in the local candidate
store; this CLI does not download a package or accept a URL.

`external_agent_update.py` exposes four operator-facing operations (plus boot
`recover` and the internal `trial-start-guard`):

```text
status
preview ARCHIVE_SHA256 CURRENT_HUB_MANIFEST_SHA256
preflight ARCHIVE_SHA256 CURRENT_HUB_MANIFEST_SHA256
apply ARCHIVE_SHA256 CURRENT_HUB_MANIFEST_SHA256 EXTERNAL_AGENT_MANIFEST_SHA256 REVIEW_SHA256
```

All operations require root. `status` returns verified Hub and external Agent
manifest hashes, the Hub-only layout flag, and whether an idle socket with the
expected ownership and mode is present. It never connects to that socket;
`live_idle_ack_verified` is therefore always false. It returns no address,
token, key, or enrollment identity. `preview` describes source paths and
checks candidate/original-Hub compatibility. `preflight` also validates the
installed tree, candidate Agent protocol files, enrollment projection, and
external baseline, then returns a review digest bound to the exact archive,
Hub and external Agent manifests, baseline, enrollment, and path changes.
Neither read-only command reserves a maintenance lease or idles the Agent.
`apply_supported=true` means the candidate has the static protocol capability;
it does not guarantee that the live lease, idle ACK, or trial will succeed.

`apply` requires the four exact lower-case SHA-256 values from a fresh
preflight. It repeats preflight and all state checks before a write, then
acquires the original Hub's authenticated command-drain lease and the old
Agent's authenticated idle ACK. An old Agent without
`/run/sovagrid-agent-control/agent.sock` fails closed before the transaction.
Such an installation needs a separately designed one-time bootstrap; this
operation does not silently replace it. The root supervisor verifies the
exact old systemd PID, invocation, cgroup, idle socket peer, and stopped state
before switching source. The external tunnel and original Hub stay in place.

The recovery journal uses `prepared`, `switched`, `trial`, and `committed`
phases. The Agent service requires the recovery unit during the trial. A crash
or lost live supervisor before commit returns the original Agent at boot.
Missing or altered source, metadata, credentials, units, or trial drop-in
causes recovery to refuse rather than guess. A live root trial gate authorizes
`recover` and `start` at most once each. The new Agent independently connects
to the root-owned Unix watchdog before Hub access and exits on a lost or
invalid heartbeat. During trial it performs metrics-only Hub cycles: it does
not claim jobs, checks, files, terminals, or command work. After a second
read-only cycle, the supervisor durably commits, sends `RELEASE`, verifies
normal dispatch in the **same Agent PID**, then sends `DETACH` and removes
temporary trial and recovery state. Post-commit recovery finishes the new
Agent instead of reverting it.

The original Hub lease, Agent idle ACK, and trial watchdog have bounded
monotonic lifetimes. A stale review, changed candidate or enrollment, expired
lease, unsafe socket, altered journal, wrong Agent peer, or failed health
check causes refusal or rollback. The optional disposable Ubuntu VM test
`tests/integrated_external_agent_apply_vm.py` exercises pre-commit rollback,
SIGKILL boot recovery, same-PID release/detach, normal dispatch, and exact
cleanup with real systemd. The root CLI remains available independently of
the optional Hub review route described below.

The optional Hub route uses a **separate fixed systemd oneshot**, not the Hub
backup broker's restricted mount namespace: atomic exchange between
`/opt/sovagrid-agent` and the recovery journal under `/var/lib` must occur on
the host filesystem. The broker accepts an exact UUID and four reviewed SHA-256
values, durably records a root-only request and status in
`/var/lib/sovagrid/external-agent-operations/<uuid>/`, then asks systemd to
start only `sovagrid-external-agent-apply@<uuid>.service`. The worker accepts
only an `accepted` request, marks it `running` under a file lock, calls the
installed CLI, and writes `complete`, `failed`, or `uncertain`. The same UUID
cannot start the update twice; after a lost response the UI reads status
instead of sending another apply. A failed unit starts the existing recovery
service, never the apply unit. The unit is installed by `run.sh --hub-only`
only when the supervising updater can snapshot and restore its marker, unit
file and operation ledger; an older updater defers first installation.
