# External Agent trial boundary

The preserved external Agent on a promoted host is not changed by the
Hub-only updater. `external_agent_update.py` exposes read-only `preview` and
`preflight`, plus boot recovery. It has no public `apply` command. The original
Agent may lack the quiescence socket, so it cannot produce the required idle
ACK for a normal update. A future one-time bootstrap needs an explicit
maintenance window and separate crash-safe approval; a Hub lease alone is not
an Agent idle proof.

`external_agent_recovery.py` prepares a journal before switching the source.
Its durable phases are `prepared`, `switched`, `trial`, and `committed`.
Pre-commit recovery returns the original Agent. Committed recovery verifies
the new tree and metadata and completes cleanup using a marker outside the
scratch directory. Missing or altered source, metadata, credentials, tunnel
units, or the trial start drop-in makes recovery refuse rather than guess.

The future root supervisor can create a private Unix socket at
`/run/sovagrid-external-agent-update/trial.sock`. The trial gate checks Linux
`SO_PEERCRED`, a fresh nonce, the SHA-256 of the exact trial journal, and
current callbacks for the original Hub maintenance lease and old Agent idle
ACK. It grants `recover` and then `start` at most once each, within 900
seconds. A stale socket, dead supervisor, expired lease, changed journal, or
lost ACK denies the request. The installed drop-in must run the root pre-start
check immediately before Agent `ExecStart` and be present in systemd's loaded
configuration.

**The live trial path remains disabled.** `recover` does not pass the optional
trial authorization callback, and `trial-start-guard` rejects a trial. A
successful `ExecStartPre` check alone leaves a gap before `ExecStart`: the
supervisor could die or lose its lease during that gap. The candidate Agent
will instead require its own live supervisor connection before any Hub request.
The static trial drop-in sets `SOVAGRID_EXTERNAL_TRIAL_GATE=1` and reads
`/run/sovagrid-external-agent-trial/epoch.env`. A future root writer must
atomically create that file as root:root mode `0600`, containing exactly
`SOVAGRID_EXTERNAL_TRIAL_EPOCH=<32 lowercase hex>`, before it starts the trial
Agent. Missing or malformed epoch data makes the new Agent refuse startup; the
old Agent ignores these variables if boot recovery rolls back its source.

The Agent runtime gate protocol is a root:sovagrid Unix socket at
`/run/sovagrid-external-agent-trial/gate.sock` under a root:sovagrid directory
mode `0710`; the socket is mode `0660`. The Agent verifies path ownership and
mode plus root `SO_PEERCRED`, sends `HELLO 1 <epoch>`, requires
`READY 1 <epoch>`, then sends `PING 0` and requires `PONG 0` before connecting
to Hub. It then sends numbered pings no more than two seconds apart and exits
on EOF, mismatch or a reply timeout above three seconds. The supervisor must
continue to prove the exact journal, original Hub lease and Agent idle ACK
before each reply. Its loss therefore prevents the new Agent from starting
across the pre-start handoff and terminates a running trial Agent.
During the trial the Agent reports metrics only: it disables command and
journal permission and starts no terminal, file, or network-check poller.
This matters because a lease could expire just after a successful heartbeat;
the trial Agent must not claim work in that interval.

The implementation also contains two dormant writer primitives.
`OriginalHubLease` authenticates to the enrolled original Hub through the
verified local TLS tunnel, acquires its 120-second job/relay drain lease,
renews it every five seconds, and invalidates itself permanently on any
failed or changed renewal. Its local 880-second limit uses monotonic time,
because the promoted host and remote Hub clocks may differ. The trial
watchdog can require a fresh renewal on each Agent heartbeat. The lease does **not** prove
that an older Agent has finished a file or command it already received.
`ExternalAgentStopProof` records the active original systemd MainPID,
invocation and cgroup. It accepts a stopped Agent only after the unit reports
inactive/dead with MainPID 0, the original process start time is gone, and
the entire cgroup-v2 subtree has no processes; it samples systemd again after
the cgroup walk to detect a concurrent start. A future writer must still hold
the start guard across this check and the source switch. These classes have
no public apply or service-stop action.

The writer still needs boot-safe installation and removal of the trial
drop-in, an old-Agent idle ACK or a separately approved one-time bootstrap,
lease-bound stop/start orchestration, live health confirmation, commit and
rollback under the existing durable journal. In particular, installing the
drop-in before the journal is durable could strand the old Agent after a
crash; merely checking `ExecStartPre` cannot solve that. None of this is
enabled on a promoted host. A signed stable update feed is a separate task.
