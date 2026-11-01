#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
# Embedded by a client only after verifying its independently pinned RUNNER
# release. stdin is that complete gzip source bundle, never the host backup.
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C PYTHONDONTWRITEBYTECODE=1
operation=
fail() {
  trap - ERR
  printf '{"ok":false,"protocol":"sovagrid-portable-restore-target-v1","operation_id":"%s","error":"%s"}\n' "$operation" "$1"
  exit 40
}
trap 'fail BOOTSTRAP_FAILED' ERR
[[ $# == 4 ]] || fail USAGE
[[ $1 =~ ^[0-9a-f]{32}$ ]] || fail INVALID_OPERATION
operation=$1
runner_bytes=$2
archive_sha=$3
manifest_sha=$4
[[ $runner_bytes =~ ^[1-9][0-9]{0,7}$ && $runner_bytes -le 67108864 &&
   $archive_sha =~ ^[0-9a-f]{64}$ && $manifest_sha =~ ^[0-9a-f]{64}$ ]] || fail INVALID_RUNNER
[[ $EUID == 0 ]] || fail ROOT_REQUIRED
[[ -r /etc/os-release ]] || fail UNSUPPORTED_TARGET
# shellcheck disable=SC1091
. /etc/os-release
[[ ${ID:-} == ubuntu && ( ${VERSION_ID:-} == 22.04 || ${VERSION_ID:-} == 24.04 || ${VERSION_ID:-} == 26.04 ) &&
   -d /run/systemd/system && $(cat /proc/1/comm) == systemd ]] || fail UNSUPPORTED_TARGET
for tool in stat sha256sum timeout head dd tar find flock sync install mktemp cmp cut; do
  command -v "$tool" >/dev/null || fail BOOTSTRAP_TOOL_UNAVAILABLE
done
[[ -d /root && ! -L /root && $(stat -c '%u:%g:%a' /root) == 0:0:700 &&
   -d /run && ! -L /run && $(stat -c '%u:%g:%a' /run) == 0:0:755 ]] || fail UNSAFE_RUNNER_PARENT
lock=/run/sovagrid-installation.lock
[[ ! -L $lock ]] || fail UNSAFE_INSTALLATION_LOCK
if [[ ! -e $lock ]]; then
  ( set -o noclobber; : > "$lock" ) 2>/dev/null || [[ -f $lock ]] || fail UNSAFE_INSTALLATION_LOCK
fi
[[ -f $lock && $(stat -c '%u:%g:%a:%h:%s' "$lock") == 0:0:600:1:0 ]] || fail UNSAFE_INSTALLATION_LOCK
exec 7>>"$lock"
[[ $(stat -Lc '%d:%i:%u:%g:%a:%h:%s' /proc/self/fd/7) == "$(stat -c '%d:%i:%u:%g:%a:%h:%s' "$lock")" ]] || fail UNSAFE_INSTALLATION_LOCK
flock -n 7 || fail BUSY
base=/root/.sovagrid-restore
work=$base/$operation
published_work=$work
fence=/var/lib/.sovagrid-host-restore-in-progress
if [[ ( -e $fence || -L $fence ) && ( ! -d $work || ! -f $work/runner.json ) ]]; then
  fail RESTORE_RECOVERY_REQUIRED
fi
if [[ ! -e $base && ! -L $base ]]; then
  install -d -o root -g root -m 0700 "$base"
  sync -f /root
fi
[[ -d $base && ! -L $base && $(stat -c '%u:%g:%a' "$base") == 0:0:700 ]] || fail UNSAFE_RUNNER_PARENT
if [[ -e $work || -L $work ]]; then
  [[ -d $work && ! -L $work && $(stat -c '%u:%g:%a' "$work") == 0:0:700 ]] || fail UNSAFE_RUNNER_PARENT
else
  # Publish runner+pin metadata as one directory. An interruption before this
  # rename leaves only an unadvertised private draft, never a half operation.
  work=$(mktemp -d "$base/.bootstrap-$operation.XXXXXXXXXXXXXXXX")
  [[ $(stat -c '%u:%g:%a' "$work") == 0:0:700 ]] || fail UNSAFE_RUNNER_PARENT
fi
# A failed stream remains private. A retry uses a fresh exclusive filename;
# interrupted files are preserved rather than guessing whether bytes changed.
incoming=$(mktemp "$work/.runner-incoming.XXXXXXXXXXXXXXXX")
[[ $(stat -c '%u:%g:%a:%h' "$incoming") == 0:0:600:1 ]] || fail UNSAFE_RUNNER
timeout 300 head -c "$runner_bytes" > "$incoming" || fail RUNNER_TRANSFER_FAILED
[[ $(stat -c '%s' "$incoming") == "$runner_bytes" ]] || fail RUNNER_TRANSFER_FAILED
extra=$(timeout 15 dd bs=1 count=1 status=none | wc -c) || fail RUNNER_TRANSFER_FAILED
[[ $extra == 0 ]] || fail RUNNER_TRANSFER_FAILED
[[ $(sha256sum "$incoming" | cut -d' ' -f1) == "$archive_sha" ]] || fail RUNNER_HASH_MISMATCH
sync -f "$incoming"
runner=$work/runner
receiver=$runner/sovagrid-blueprint/deploy/portable_restore_receiver.py
if [[ -e $runner || -L $runner || -e $work/runner.json || -L $work/runner.json ]]; then
  [[ -x /usr/bin/python3 && -d $runner && ! -L $runner && -f $work/runner.json && ! -L $work/runner.json &&
     $(stat -c '%u:%g:%a:%h' "$work/runner.json") == 0:0:600:1 ]] || fail INCOMPLETE_RUNNER
  # Verify the EXISTING tree with embedded stdlib code before importing its
  # receiver. Bytecode, links, extra paths and writable source are forbidden.
  /usr/bin/python3 -B -I -c '
import hashlib,json,os,pathlib,re,stat,sys
root=pathlib.Path(sys.argv[1]); expected_archive,expected_manifest,operation=sys.argv[2:]
record=json.loads((root.parent/"runner.json").read_bytes())
assert record["operation_id"]==operation and record["runner_archive_sha256"]==expected_archive and record["runner_manifest_sha256"]==expected_manifest
raw=(root/"sovagrid-bundle.json").read_bytes(); assert hashlib.sha256(raw).hexdigest()==expected_manifest
manifest=json.loads(raw); hashes=manifest["sha256"]; actual=set(); allowed=set(manifest["components"])
for name in hashes:
 assert re.fullmatch(r"[A-Za-z0-9_.@-]+(?:/[A-Za-z0-9_.@-]+)*",name) and not any(p in (".","..") for p in name.split("/"))
 allowed.update(str(p) for p in pathlib.Path(name).parents if str(p)!=".")
for parent,dirs,files in os.walk(root,followlinks=False):
 for name in dirs+files:
  path=pathlib.Path(parent)/name; info=path.lstat(); rel=path.relative_to(root).as_posix()
  assert info.st_uid==info.st_gid==0 and not info.st_mode&0o022
  if name in dirs: assert stat.S_ISDIR(info.st_mode) and rel in allowed
  else:
   assert stat.S_ISREG(info.st_mode) and info.st_nlink==1 and (rel in hashes or rel=="sovagrid-bundle.json")
   if rel in hashes: assert hashlib.sha256(path.read_bytes()).hexdigest()==hashes[rel]; actual.add(rel)
assert actual==set(hashes)
' "$runner" "$archive_sha" "$manifest_sha" "$operation" >/dev/null 2>&1 || fail RUNNER_HASH_MISMATCH
else
  [[ ! -e $fence && ! -L $fence ]] || fail RESTORE_RECOVERY_REQUIRED
  # The archive digest is an independent release pin, not a checksum supplied
  # by a backup. Still restrict tar to the five regular source trees.
  listing=$(mktemp "$work/.runner-list.XXXXXXXXXXXXXXXX")
  tar -tzf "$incoming" > "$listing" || fail INVALID_RUNNER
  while IFS= read -r name; do
    name=${name%/}
    [[ $name =~ ^[A-Za-z0-9_.@-]+(/[A-Za-z0-9_.@-]+)*$ &&
       $name != /* && $name != *//* && ! /$name/ =~ /\.\.?/ ]] || fail INVALID_RUNNER
    case $name in
      sovagrid-bundle.json|sovagrid-blueprint|sovagrid-blueprint/*|sovagrid-hub|sovagrid-hub/*|sovagrid-web|sovagrid-web/*|sovagrid-agent|sovagrid-agent/*|sovagrid-vpn|sovagrid-vpn/*) ;;
      *) fail INVALID_RUNNER ;;
    esac
  done < "$listing"
  tar -tvzf "$incoming" | awk 'substr($0,1,1)!="-" && substr($0,1,1)!="d" {exit 1}' || fail INVALID_RUNNER
  staged=$(mktemp -d "$work/.runner-stage.XXXXXXXXXXXXXXXX")
  tar -xzf "$incoming" -C "$staged" --no-same-owner --same-permissions || fail INVALID_RUNNER
  [[ -f $staged/sovagrid-bundle.json && ! -L $staged/sovagrid-bundle.json &&
     $(stat -c '%u:%g:%a:%h' "$staged/sovagrid-bundle.json") == 0:0:644:1 &&
     $(sha256sum "$staged/sovagrid-bundle.json" | cut -d' ' -f1) == "$manifest_sha" ]] || fail RUNNER_HASH_MISMATCH
  [[ -z $(find "$staged" \( ! -user root -o ! -group root -o -perm /022 -o \( ! -type f -a ! -type d \) \) -print -quit) ]] || fail INVALID_RUNNER
  [[ -f $staged/sovagrid-blueprint/run.sh && -f $staged/sovagrid-blueprint/deploy/portable_restore_receiver.py ]] || fail INVALID_RUNNER
  chmod 0755 "$staged"
  staged_inode=$(stat -c '%d:%i' "$staged")
  mv -T -n -- "$staged" "$runner"
  [[ $(stat -c '%d:%i' "$runner") == "$staged_inode" ]] || fail RUNNER_DESTINATION_EXISTS
  sync -f "$work"
  metadata=$(mktemp "$work/.runner-metadata.XXXXXXXXXXXXXXXX")
  printf '{"protocol":"sovagrid-portable-restore-runner-v1","operation_id":"%s","runner_bytes":%s,"runner_archive_sha256":"%s","runner_manifest_sha256":"%s","dependencies_ready":false}\n' \
    "$operation" "$runner_bytes" "$archive_sha" "$manifest_sha" > "$metadata"
  sync -f "$metadata"
  mv -T -n -- "$metadata" "$work/runner.json"
  [[ ! -e $metadata && $(stat -c '%u:%g:%a:%h' "$work/runner.json") == 0:0:600:1 ]] || fail RUNNER_DESTINATION_EXISTS
  sync -f "$work"
fi
if [[ $work != "$published_work" ]]; then
  work_inode=$(stat -c '%d:%i' "$work")
  mv -T -n -- "$work" "$published_work"
  [[ $(stat -c '%d:%i' "$published_work") == "$work_inode" ]] || fail RUNNER_DESTINATION_EXISTS
  incoming=$published_work/${incoming##*/}
  work=$published_work
  runner=$work/runner
  receiver=$runner/sovagrid-blueprint/deploy/portable_restore_receiver.py
  sync -f "$base"
fi
# The fully received, hash-proven temporary belongs to this invocation.
rm -- "$incoming"
if [[ -e $fence || -L $fence ]]; then
  /usr/bin/python3 -B -I "$receiver" runner-status "$operation"
  exit 0
fi
log=$(mktemp "$work/.dependencies-log.XXXXXXXXXXXXXXXX")
SOVAGRID_INSTALLATION_LOCK_FD=7 /bin/bash "$runner/sovagrid-blueprint/run.sh" \
  --restore-dependencies-only --expected-source-manifest-sha256 "$manifest_sha" > "$log" 2>&1 || fail DEPENDENCIES_FAILED
/usr/bin/python3 -B -I -c '
import json,os,pathlib,tempfile,sys
root=pathlib.Path("/root/.sovagrid-restore")/sys.argv[1]
record=json.loads((root/"runner.json").read_bytes()); record["dependencies_ready"]=True
fd,name=tempfile.mkstemp(prefix=".runner-ready.",dir=root)
with os.fdopen(fd,"w") as output:
 json.dump(record,output,sort_keys=True,separators=(",",":")); output.write("\n"); output.flush(); os.fsync(output.fileno())
os.replace(name,root/"runner.json")
fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); os.fsync(fd); os.close(fd)
' "$operation" >/dev/null 2>&1 || fail RUNNER_STATE_FAILED
/usr/bin/python3 -B -I "$receiver" runner-status "$operation"
