# Portable restore from Web and PWA

The administrator can select **Restore onto another server** beside a verified
portable backup, or open the five-file import in Settings. No console, locally
installed SSH client, arbitrary script, or browser-supplied filesystem path is
needed. The target requires Ubuntu and root SSH or configured noninteractive
sudo. An optional SSH relay has its own separately reviewed host key and login.

The wizard first delivers an independently pinned runner, installs missing
target dependencies, streams the immutable backup and shows the target's plan.
Applying that plan requires a second confirmation. The UI follows the selected
runner's `apply_available` capability and displays its refusal reasons. It
cannot enable a backend that has not passed its release gate. Existing SovaGrid
data, unsupported routing state and unsupported public address changes refuse
before apply. Queued jobs and Telegram confirmations are cancelled; VPN
configuration is restored with its interfaces down.

## Five-file import

Select the original `<archive-id>.tar.gz`, `<archive-id>.manifest.json`,
`images.tar`, `manifest.json` and `receipt.json` from a portable v2 export. The
browser reads only bounded metadata and at most 4 MiB of an archive at a time.
The gateway accepts a small fixed JSON header and raw binary chunk, never a
gigabyte JSON/base64 request. The root service checks offsets, chunk hashes and
each final full-file SHA-256. Archive bytes remain data until the separately
confirmed target restore verifies and processes them.

Each archive is bounded to 8 GiB; all five files together to 16 GiB. A source
has at most 8192 immutable chunk receipts. There are at most 16 imported sources
and 128 operation records. Admission fails before creating a 129th operation.
History shows the latest eight entries; any older retained operation can be
opened by its ID. Explicit import deletion removes only the local cache and its
import receipt; it preserves operation metadata and target data. An interrupted
transfer can then resume by selecting that operation and the same five files.

The dedicated native panel bridge is detected at click time and after
`sovagrid-native-restore-ready`. It returns File-like objects with `name`,
`size`, `slice(start,end).arrayBuffer()` and optional `release()`. The ordinary
native upload limit remains unchanged. Closing the wizard, switching accounts
or sources and finishing an upload release selected native file grants. Late
picker, key-file or network replies cannot populate a different session.

## Durable state and cache

Small nonsecret journals live in:

```
/var/lib/sovagrid/web-agent/restores/{imports,operations}/<32-hex-id>/
```

Only `.lock`, `state.json` and interrupted `.<32-hex-id>.tmp` files are used.
Files are root:root 0600, directories 0700, state at most 2 MiB. These journals
are included in managed backups and existing updater snapshots. They retain the
source IDs, five immutable hashes/sizes, target and optional relay pins, runner
archive/manifest pins, operation ID and confirmation revision. They contain no
passwords, private keys, SSH passphrases or Hub session tokens. Old pinned runner
bundles remain protected from pruning while these records reference them.

Large bytes live only in the excluded cache:

```
/var/cache/sovagrid-web-restores/imports/<source-id>/
```

The cache has only those five canonical filenames. New directory entries,
files, chunk bytes and metadata publication are fsynced before acknowledgement.
Each part has an inode binding and durable pending-chunk intent, so a lost reply
resumes or acknowledges the exact existing prefix. A whole excluded cache lost
during migration can be re-uploaded using the retained hashes. Explicit removal
accepts only the closed private-file inventory and refuses foreign entries.

The service uses systemd `StateDirectory=sovagrid/web-agent/restores` and
`CacheDirectory=sovagrid-web-restores`, both mode 0700. It validates ownership
and modes rather than adopting foreign data. The cache filesystem supplies the
free-space check. Server-held portable backups stream through held verified
file descriptors directly from their managed locations without a second large
cache copy.

The installer advertises `# SOVAGRID_WEB_RESTORE_V1` and verifies the fixed
helper, vendored Python and Web asset closure before activation. It checks
existing namespace directories and their ancestors before systemd can adopt
them: existing leaves must be root:root 0700 directories, with no symlinks or
writable ancestors. An unsafe existing path refuses installation without
changing ownership or permissions. All updater paths detect the restore
metadata namespace, including an unsafe or broken link, and refuse candidates
that remove the marker or fixed runtime files. The existing recursive Web Agent
snapshot and its legacy indices remain unchanged; bulk cache is still excluded.

## Authentication and reconnect

Every gateway request requires same-origin HTTPS or a loopback origin and a
fresh unrestricted Hub administrator. Root rechecks that role before reading
an upload body and again before dispatch, during preparation progress, and
before and after each remote operation. SSH passwords live in a private
headless askpass broker; private-key files exist only in the private runtime
transport and are removed on close. Neither is put in a journal or command
argument. Target and relay use independent strict known-host pins.

Long preparation holds the common installation/source guard so source backups
and source swaps wait. Target apply runs detached under its saved operation ID;
closing the page does not stop it. Reopening uses saved local metadata and fresh
SSH credentials, then checks the target's current operation. An uncertain start
is checked with status and is never automatically replayed. Recover and retry
require the current revision and server-provided capabilities; a retry produces
a fresh plan which needs its own apply confirmation. Remote status and recovery
remain available after the local source/cache is gone.

Protocol details are in [PORTABLE_RESTORE_TARGET.md](PORTABLE_RESTORE_TARGET.md).
