# Target restore transport

This is the client integration contract for the portable restore wizard. It is
not an end-user installation command. The production apply gate remains closed
until the complete disposable Ubuntu checks pass.

The client separately obtains and verifies a pinned SovaGrid source release.
Executable helpers come from that release, never from the selected backup. The
helper tree stays in `/root/.sovagrid-restore/<operation_id>/runner`; publishing
the restored `/opt/sovagrid-src` cannot replace the recovery implementation.

## Bootstrap

The pinned archive contains `deploy/portable_restore_bootstrap.sh`. Invoke its
verified bytes with `/bin/bash -c SCRIPT -- OP BYTES ARCHIVE_SHA MANIFEST_SHA`,
and send exactly that complete runner archive on stdin. Root or existing
passwordless sudo is required. The target must be Ubuntu 22.04, 24.04 or 26.04
with systemd. No sudo password is collected.

The script holds the shared installation lock, verifies the independent archive
and manifest pins, restricts extraction to the five source components, and
publishes a private operation directory containing both runner and metadata in
one rename. A crash before publication leaves an unadvertised private draft.
An existing published operation is reverified before any helper is imported.
The source archive and the private pin record are immutable for that operation.

Dependencies are installed through `run.sh --restore-dependencies-only`; no
SovaGrid account, Hub, Agent or live configuration is installed. Dependency
output goes to a root-private log. Successful stdout is one JSON object:

```json
{"ok":true,"protocol":"sovagrid-portable-restore-target-v1","operation_id":"OP","runner_archive_sha256":"SHA","runner_manifest_sha256":"SHA","dependencies_ready":true}
```

When an existing restore fence is present, bootstrap verifies its existing
runner and reports its recorded readiness without running dependency changes.
This permits reconnection for status/recovery. A new operation is refused.

The combined disposable Ubuntu gate runs `tests/portable_restore_bootstrap_vm.py`
after dependencies and before the full installation. It verifies the original
source bundle, streams it through the real bootstrap twice with the same
operation, checks exact ready pins and the retained runner inode, then tests a
tiny binary upload and receiver reconnection. It creates no SovaGrid accounts,
services or live configuration. This prepared check still requires a successful
hosted VM run; local tests do not open the production apply gate.

## One SSH stream

Run the verified receiver with `/usr/bin/python3 -B -I RECEIVER serve OP`.
Commands are ASCII JSON lines, at most 64 KiB each. Every command returns one
JSON line and flushes it. A receive command is immediately followed by exactly
its declared binary length; no separator or EOF follows those bytes. This lets
all five files use one authenticated SSH session on every desktop platform.

Malformed or refused frames return a bounded error and close the stream.
Reconnect and read status; remaining binary bytes are never reinterpreted as a
new command after an error. Errors expose only uppercase machine codes, no
traceback, input payload, credential or private log contents.

| Action | Exact additional fields |
| --- | --- |
| `init` | `request` |
| `receive` | `part`, `offset`, `length`, `sha256`, then binary bytes |
| `status` | none |
| `register` | none |
| `deps` | none |
| `preview` | none |
| `start` | `apply_review_sha256` |
| `operation-status` | none |
| `recover` | none |
| `retry` | `terminal_sha256` |

`OP` and archive IDs are 32 lowercase hexadecimal characters. Digests are 64
lowercase hexadecimal characters. Offsets and lengths are integers, not booleans.
The maximum chunk is 4 MiB. No action accepts a path, shell command, unit
property or persisted SSH credential.

The immutable request has exactly `protocol`, `operation_id`, `archive_id`,
`runner_archive_sha256`, `runner_manifest_sha256` and `artifacts`. Artifacts
has exactly `host_manifest`, `host`, `images_manifest`, `images`, `receipt`;
each value has exactly positive `bytes` and `sha256`. Host/image archives are
bounded to 8 GiB each, image manifest to 4096 bytes and receipt to 8192 bytes.
Metadata is bound to the held local files before transfer.

Transfer replies share `ok`, `protocol`, `operation_id`, `archive_id`,
`request_sha256`, `registered`, `max_chunk_bytes`, `pending_chunk`, `artifacts`.
`request_sha256` hashes canonical sorted compact JSON plus a final LF.
Each artifact reports `received`, `bytes`, `sha256`, `complete`.
`pending_chunk` is null or `{part,offset,length,sha256}`. A client resumes that
exact fragment; it cannot substitute a different payload. Durable intent and
an inode seal precede data writes. Repeated acknowledged chunks are idempotent.

Registration validates the host archive, source map, Docker image layers and
receipt with the pinned validators before publishing fixed input filenames.
Copies use bounded buffers and exact inode proofs. Interrupted publication
resumes only its own matching prefix. An existing foreign destination is
preserved even when its bytes match. All five final files are root-private.

## Review, detached execution and retry

The required-space preview includes an additional 8 GiB reserve for bounded
image-content verification across Docker storage formats. If a daemon assigns
a new image ID during import, the runner re-exports only the fixed service
tags into an anonymous private staging file and verifies the exact original
configuration digest, RootFS and platform. Only a digest bound by that verified
image graph may become a Compose image reference. This requires no new public
manifest or receipt field and never permits pruning unrelated daemon data.

`preview` stages the verified inputs and checks the complete common resource
plan, dependencies, identities, unit graph, endpoint and free space. Its reply
has `phase:review`, nested `preview`, `backend_supported`, `target_ready`,
`apply_available`, `blockers` and `apply_review_sha256`, plus the common
operation/archive/request binding. Physical readiness is separate from the
production apply gate. The final CAS binds both, the resource plan, policy and
attempt revision; a changed or delayed review cannot start another attempt.

The review explicitly reports that archived queued commands and Telegram
confirmations are canceled before any activation, and VPN configuration is
restored with interfaces down. Unsupported layouts, v1 receipts, kernel
routing state, custom file roots and a changed public address block the review
before confirmation. There is no implicit public-address remapping.

`start` records a durable intent then starts fixed-argv transient systemd work.
Its control lock is released before starting systemd so an immediately launched
worker can acquire the lock and advance that intent.
Closing SSH or the application does not terminate it. An uncertain/repeated
start returns status and never repeats apply. Workers validate a fresh nonce
and hold a private process lock. No credentials are stored in that intent.

`operation-status` returns `phase`, `worker_active`, `action`, `kernel_status`,
`backend_supported`, `retry_available`, `retry_in_progress`, `terminal_sha256`, `error`, and the
common operation binding. It remains readable while the transaction runs.
Recovery is independent of the forward-apply gate and is an explicit action.

After a fully `rolled_back` transaction, `retry` requires its exact terminal
digest and a clean target. It archives the original journal/plan/Compose files
by their sealed inodes and hashes, preserves history, and issues a fresh attempt
nonce. Interruption of that archival must finish before another apply can
begin. A partially archived retry remains readable as `phase:retry_required` with its retained terminal digest, even after the live kernel journal moved. The next start requires a new preview. `recovery_required` with changed
runtime data preserves those data and the persistent fence; another apply is
not a safe substitute for recovery.
