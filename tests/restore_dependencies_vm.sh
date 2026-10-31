#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
# Run only on a disposable, clean Ubuntu VM after unpacking a reviewed bundle
# under /root. Usage: sudo ./tests/restore_dependencies_vm.sh MANIFEST_SHA256
set -euo pipefail
umask 077

fail() { printf 'restore bootstrap VM test: %s\n' "$*" >&2; exit 1; }
[[ $EUID == 0 ]] || fail 'run as root on a disposable Ubuntu VM'
[[ ${1:-} =~ ^[0-9a-f]{64}$ && $# == 1 ]] || fail 'provide the reviewed bundle manifest SHA-256'
run=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)/run.sh
worker=$(dirname -- "$run")/deploy/remote_update_worker.py
[[ $run == /root/* ]] || fail 'unpack the bundle under /root first'
[[ -f $worker ]] || fail 'reviewed bundle is incomplete'
digest=$1
args=(--restore-dependencies-only --expected-source-manifest-sha256 "$digest")
marker=/etc/sovagrid-restore-bootstrap-smoke
execution_marker=/run/sovagrid-restore-bootstrap-execution-marker
backup=$(mktemp)
worker_saved=0
docker_data_created=0
cleanup() {
  if (( worker_saved )); then cp -p -- "$backup" "$worker"; fi
  rm -f -- "$backup" "$execution_marker"
  rmdir -- "$marker" 2>/dev/null || true
  if (( docker_data_created )); then
    rm -f -- /var/lib/docker/.sovagrid-restore-bootstrap-smoke
    rmdir -- /var/lib/docker 2>/dev/null || true
  fi
}
trap cleanup EXIT
[[ ! -e $marker && ! -L $marker && ! -e $execution_marker ]] ||
  fail 'test marker already exists; refusing to overwrite it'

before=$(dpkg-query -W -f='${Package} ${Version}\n' | sha256sum | cut -d' ' -f1)
mkdir -m 0700 -- "$marker"
if "$run" "${args[@]}" >/dev/null 2>&1; then fail 'dirty target was accepted'; fi
after=$(dpkg-query -W -f='${Package} ${Version}\n' | sha256sum | cut -d' ' -f1)
[[ $before == "$after" ]] || fail 'dirty target changed the OS package set'
rmdir -- "$marker"

if [[ ! -e /usr/bin/docker && ! -e /var/lib/docker && ! -L /var/lib/docker ]]; then
  mkdir -m 0700 -- /var/lib/docker
  docker_data_created=1
  printf 'retained\n' > /var/lib/docker/.sovagrid-restore-bootstrap-smoke
  if "$run" "${args[@]}" >/dev/null 2>&1; then
    fail 'retained Docker data was accepted without a local Docker CLI'
  fi
  after=$(dpkg-query -W -f='${Package} ${Version}\n' | sha256sum | cut -d' ' -f1)
  [[ $before == "$after" ]] || fail 'retained Docker data changed the OS package set'
  rm -f -- /var/lib/docker/.sovagrid-restore-bootstrap-smoke
  rmdir -- /var/lib/docker
  docker_data_created=0
fi

# If the bootstrap imports candidate Python before hashing it, this line runs.
cp -p -- "$worker" "$backup"
worker_saved=1
printf '\nopen("%s", "w").write("executed")\n' "$execution_marker" >> "$worker"
if "$run" "${args[@]}" >/dev/null 2>&1; then fail 'tampered candidate was accepted'; fi
[[ ! -e $execution_marker ]] || fail 'tampered candidate code executed before verification'
cp -p -- "$backup" "$worker"
worker_saved=0

DOCKER_HOST=tcp://127.0.0.1:1 DOCKER_CONTEXT=nonexistent-restore-test "$run" "${args[@]}"
command -v python3 >/dev/null || fail 'Python is missing'
[[ -x /usr/bin/docker && -x /usr/bin/ss ]] || fail 'restore dependencies are incomplete'
local_docker() {
  env -u DOCKER_HOST -u DOCKER_CONTEXT /usr/bin/docker --host unix:///var/run/docker.sock "$@"
}
local_docker compose version >/dev/null || fail 'Docker Compose is missing'

for path in /etc/sovagrid* /opt/sovagrid* /var/lib/sovagrid* \
            /usr/local/bin/sovagrid* /usr/local/libexec/sovagrid*; do
  case $path in
    /var/lib/sovagrid-host-backups|/var/lib/sovagrid-host-image-exports) continue ;;
  esac
  [[ ! -e $path && ! -L $path ]] || fail "SovaGrid state was created: $path"
done
[[ -z $(find /etc/systemd/system -name 'sovagrid-*' -print -quit) ]] ||
  fail 'SovaGrid systemd unit was created'
if getent passwd | cut -d: -f1 | grep -Eq '^sovagrid([_-]|$)' ||
   getent group | cut -d: -f1 | grep -Eq '^sovagrid([_-]|$)'; then
  fail 'SovaGrid identity was created'
fi
for kind in containers images networks volumes; do
  case $kind in
    containers) inventory=$(local_docker ps -a --format '{{.Names}}') ;;
    images) inventory=$(local_docker image ls -a --format '{{.Repository}}') ;;
    networks) inventory=$(local_docker network ls --format '{{.Name}}') ;;
    volumes) inventory=$(local_docker volume ls --format '{{.Name}}') ;;
  esac
  if printf '%s\n' "$inventory" | grep -Eq '(^|/)sovagrid([-_/]|$)'; then
    fail "SovaGrid Docker $kind were created"
  fi
done
printf 'restore bootstrap VM test passed\n'
