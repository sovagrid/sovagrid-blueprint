#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
# Install or update only the SovaGrid stack on an Ubuntu host.
# SOVAGRID_JOURNAL_INSTALL_V1
# SOVAGRID_CONTAINER_INVENTORY_V1
# SOVAGRID_PUBLIC_WEB_V1
# SOVAGRID_LOCAL_WEB_V1
# SOVAGRID_RELEASE_FEED_UNITS_V1
# SOVAGRID_HUB_BACKUP_BROKER_V1
# SOVAGRID_SSH_GATEWAY_INSTALL_V1
# SOVAGRID_WEB_AGENT_INSTALL_V1
set -euo pipefail
umask 077
# Keep the verified source tree free of generated Python bytecode on fresh installs.
export PYTHONDONTWRITEBYTECODE=1

die() { printf 'SovaGrid: %s\n' "$*" >&2; exit 1; }
say() { printf 'SovaGrid: %s\n' "$*"; }

[[ ${EUID} -eq 0 ]] || die 'run as root (sudo ./run.sh)'
[[ -r /etc/os-release ]] || die 'cannot identify the operating system'
# shellcheck disable=SC1091
. /etc/os-release
[[ ${ID:-} == ubuntu ]] || die 'this installer currently supports Ubuntu only'
# An older SSH updater does not snapshot the new timer units. Refuse before
# changing this host if it supervises an upgrade without that rollback support.
if [[ ${SOVAGRID_PUBLIC_WEB_LOCK_HELD:-0} == 1 && -f /var/lib/sovagrid/.managed-by-run-sh && ${SOVAGRID_UPDATER_TIMER_SNAPSHOT:-0} != 1 ]]; then
  die 'the SSH updater must support the auto-update timer rollback snapshot'
fi

# An older updater cannot roll back this root service, its request ledger or
# the Hub container's socket mount. Its first upgrade must leave them absent.
backup_broker_marker=/var/lib/sovagrid/.hub-backup-broker-managed-by-run-sh
backup_broker_deferred=0
if [[ ${SOVAGRID_PUBLIC_WEB_LOCK_HELD:-0} == 1 && -f /var/lib/sovagrid/.managed-by-run-sh &&
      ${SOVAGRID_HUB_BACKUP_BROKER_SNAPSHOT:-0} != 1 ]]; then
  backup_broker_deferred=1
  for backup_path in "$backup_broker_marker" \
                     /etc/systemd/system/sovagrid-hub-backup-control.socket \
                     /etc/systemd/system/sovagrid-hub-backup-control.service \
                     /var/lib/sovagrid/backups/.broker-requests; do
    [[ ! -e $backup_path && ! -L $backup_path ]] || die 'the supervising updater cannot snapshot the Hub backup broker'
  done
fi
# A previous worker can deliver this release but cannot restore feed units or
# its anti-replay state. Defer their first installation until the newly
# installed worker supervises an update (or an administrator reruns run.sh).
release_feed_deferred=0
release_feed_marker=/var/lib/sovagrid/.release-feed-units-managed-by-run-sh
if [[ ${SOVAGRID_PUBLIC_WEB_LOCK_HELD:-0} == 1 && -f /var/lib/sovagrid/.managed-by-run-sh &&
      ${SOVAGRID_RELEASE_FEED_SNAPSHOT:-0} != 1 ]]; then
  release_feed_deferred=1
  for feed_path in "$release_feed_marker" /etc/sovagrid/release-feed.json \
                   /var/lib/sovagrid/release-feed-state.json \
                   /etc/systemd/system/sovagrid-release-feed.service \
                   /etc/systemd/system/sovagrid-release-feed.timer; do
    [[ ! -e $feed_path && ! -L $feed_path ]] || die 'the supervising updater cannot snapshot existing release-feed state'
  done
fi

# The previous updater knows only Hub/Web images. Its first transition to
# this source may update those two services, but must leave the new gateway
# absent so a rollback cannot strand a third container outside its snapshot.
ssh_gateway_marker=/var/lib/sovagrid/.ssh-gateway-managed-by-run-sh
ssh_gateway_marker_content='SOVAGRID_SSH_GATEWAY_V1'
ssh_gateway_deferred=0
if [[ ${SOVAGRID_PUBLIC_WEB_LOCK_HELD:-0} == 1 && -f /var/lib/sovagrid/.managed-by-run-sh &&
      ${SOVAGRID_SSH_GATEWAY_SNAPSHOT:-0} != 1 ]]; then
  ssh_gateway_deferred=1
  [[ ! -e $ssh_gateway_marker && ! -L $ssh_gateway_marker ]] ||
    die 'the supervising updater cannot snapshot the SSH gateway'
fi
if [[ -e $ssh_gateway_marker || -L $ssh_gateway_marker ]]; then
  [[ -f $ssh_gateway_marker && ! -L $ssh_gateway_marker &&
     $(stat -c '%u:%g:%a:%h' "$ssh_gateway_marker") == 0:0:600:1 ]] ||
    die 'SSH gateway marker is unsafe'
  cmp -s -- "$ssh_gateway_marker" <(printf '%s\n' "$ssh_gateway_marker_content") ||
    die 'SSH gateway marker is unsafe'
fi

# A previous updater cannot restore the new root service, socket, or its
# private enrollment journal. Its first upgrade leaves this feature absent.
web_agent_marker=/var/lib/sovagrid/.web-agent-installer-managed-by-run-sh
web_agent_deferred=0
if [[ ${SOVAGRID_PUBLIC_WEB_LOCK_HELD:-0} == 1 && -f /var/lib/sovagrid/.managed-by-run-sh &&
      ${SOVAGRID_WEB_AGENT_SNAPSHOT:-0} != 1 ]]; then
  web_agent_deferred=1
  for web_agent_path in "$web_agent_marker" /var/lib/sovagrid/web-agent \
                        /etc/systemd/system/sovagrid-web-agent-control.socket \
                        /etc/systemd/system/sovagrid-web-agent-control.service; do
    [[ ! -e $web_agent_path && ! -L $web_agent_path ]] ||
      die 'the supervising updater cannot snapshot the Web Agent installer'
  done
fi
if [[ -e $web_agent_marker || -L $web_agent_marker ]]; then
  [[ -f $web_agent_marker && ! -L $web_agent_marker &&
     $(stat -c '%u:%g:%a:%h' "$web_agent_marker") == 0:0:600:1 ]] ||
    die 'Web Agent installer marker is unsafe'
  cmp -s -- "$web_agent_marker" <(printf '%s\n' 'SOVAGRID_WEB_AGENT_INSTALL_V1') ||
    die 'Web Agent installer marker is unsafe'
fi

hub_only=0
with_wireguard=0
with_terminal=0
with_journal=0
with_containers=0
terminal_requested=0
files_requested=0
journal_requested=0
journal_disable_requested=0
containers_requested=0
containers_disable_requested=0
journal_units=()
while (( $# )); do
  case $1 in
    --hub-only) (( ! hub_only )) || die 'duplicate --hub-only'; hub_only=1 ;;
    --with-wireguard) (( ! with_wireguard )) || die 'duplicate --with-wireguard'; with_wireguard=1 ;;
    --with-terminal) (( ! terminal_requested )) || die 'duplicate --with-terminal'; with_terminal=1; terminal_requested=1 ;;
    --with-files) (( ! files_requested )) || die 'duplicate --with-files'; files_requested=1 ;;
    --with-journal) (( ! journal_requested )) || die 'duplicate --with-journal'; journal_requested=1 ;;
    --disable-journal) (( ! journal_disable_requested )) || die 'duplicate --disable-journal'; journal_disable_requested=1 ;;
    --with-containers) (( ! containers_requested )) || die 'duplicate --with-containers'; containers_requested=1 ;;
    --disable-containers) (( ! containers_disable_requested )) || die 'duplicate --disable-containers'; containers_disable_requested=1 ;;
    --journal-unit)
      (( $# >= 2 )) || die '--journal-unit needs one exact .service name'
      [[ $2 =~ ^[A-Za-z0-9_.@-]{1,96}\.service$ ]] || die 'invalid journal unit; use an exact .service name (1–96 characters before suffix)'
      for existing in "${journal_units[@]}"; do [[ $existing != "$2" ]] || die 'duplicate journal unit'; done
      journal_units+=("$2")
      (( ${#journal_units[@]} <= 16 )) || die 'no more than 16 journal units are allowed'
      shift
      ;;
    *) die 'usage: sudo ./run.sh [--hub-only] [--with-wireguard] [--with-terminal] [--with-files] [--with-journal --journal-unit NAME.service ... | --disable-journal] [--with-containers | --disable-containers]' ;;
  esac
  shift
done
if (( journal_requested )); then
  (( ! journal_disable_requested )) || die '--with-journal conflicts with --disable-journal'
  (( ${#journal_units[@]} >= 1 )) || die '--with-journal requires 1–16 --journal-unit NAME.service entries'
  with_journal=1
else
  (( ${#journal_units[@]} == 0 )) || die '--journal-unit requires --with-journal'
fi
if (( ! hub_only )) && [[ -f /etc/sovagrid/.terminal-unit-managed-by-run-sh ]]; then with_terminal=1; fi
if (( ! hub_only && ! journal_disable_requested )) && [[ -f /etc/sovagrid/.journal-managed-by-run-sh ]]; then with_journal=1; fi
(( ! containers_requested || ! containers_disable_requested )) || die '--with-containers conflicts with --disable-containers'
if (( ! hub_only && ! containers_disable_requested )) && [[ -f /etc/sovagrid/.containers-managed-by-run-sh ]]; then with_containers=1; fi
if (( containers_requested )); then with_containers=1; fi
(( ! hub_only || ! with_terminal )) || die '--with-terminal requires the host Agent'
(( ! hub_only || ! files_requested )) || die '--with-files requires the host Agent'
(( ! hub_only || ! journal_requested )) || die '--with-journal requires the host Agent'
(( ! hub_only || ! journal_disable_requested )) || die '--disable-journal requires the host Agent'
(( ! hub_only || ! containers_requested )) || die '--with-containers requires the host Agent'
(( ! hub_only || ! containers_disable_requested )) || die '--disable-containers requires the host Agent'
if (( containers_disable_requested )); then
  [[ -f /etc/sovagrid/.containers-managed-by-run-sh && ! -L /etc/sovagrid/.containers-managed-by-run-sh &&
     $(stat -c '%U:%G:%a' /etc/sovagrid/.containers-managed-by-run-sh) == root:root:600 ]] || die 'no safe SovaGrid-managed container inventory to disable'
fi
if (( journal_disable_requested )); then
  journal_marker=/etc/sovagrid/.journal-managed-by-run-sh
  [[ -f $journal_marker && ! -L $journal_marker &&
     $(stat -c '%U:%G:%a' "$journal_marker") == root:root:600 ]] || die 'no safe SovaGrid-managed journal broker to disable'
  if [[ -e /etc/sovagrid-journal || -L /etc/sovagrid-journal ]]; then
    [[ -d /etc/sovagrid-journal && ! -L /etc/sovagrid-journal &&
       $(stat -c '%u:%a' /etc/sovagrid-journal) == 0:750 ]] || die 'journal policy directory is unsafe'
    [[ -z $(find /etc/sovagrid-journal -mindepth 1 -maxdepth 1 ! -name units.json -print -quit) ]] || die 'journal policy directory has unexpected files'
    if [[ -e /etc/sovagrid-journal/units.json || -L /etc/sovagrid-journal/units.json ]]; then
      [[ -f /etc/sovagrid-journal/units.json && ! -L /etc/sovagrid-journal/units.json &&
         $(stat -c '%u:%a' /etc/sovagrid-journal/units.json) == 0:640 ]] || die 'journal policy file is unsafe'
    fi
  fi
  for managed_unit in sovagrid-journal-control.service sovagrid-journal-control.socket; do
    if [[ -e /etc/systemd/system/$managed_unit || -L /etc/systemd/system/$managed_unit ]]; then
      [[ -f /etc/systemd/system/$managed_unit && ! -L /etc/systemd/system/$managed_unit &&
         $(stat -c '%U:%G:%a' "/etc/systemd/system/$managed_unit") == root:root:644 ]] || die "managed $managed_unit is unsafe"
    fi
  done
fi
if (( ! hub_only )) && [[ -e /etc/systemd/system/sovagrid-agent.service && ! -f /etc/sovagrid/.agent-unit-managed-by-run-sh ]]; then
  die 'an unmanaged sovagrid-agent.service already exists; inspect it before installing the Agent'
fi
if [[ -e /etc/systemd/system/sovagrid-vpn-status.service && ! -f /etc/sovagrid/.vpn-unit-managed-by-run-sh ]]; then
  die 'an unmanaged sovagrid-vpn-status.service already exists; inspect it before installing the VPN inventory'
fi
if [[ -e $release_feed_marker || -L $release_feed_marker ]]; then
  [[ -f $release_feed_marker && ! -L $release_feed_marker &&
     $(stat -c '%U:%G:%a:%h' "$release_feed_marker") == root:root:600:1 ]] || die 'release-feed ownership marker is unsafe'
  cmp -s -- "$release_feed_marker" <(printf 'SOVAGRID_RELEASE_FEED_UNITS_V1\n') || die 'release-feed ownership marker is invalid'
fi
for feed_unit in sovagrid-release-feed.service sovagrid-release-feed.timer; do
  feed_destination=/etc/systemd/system/$feed_unit
  if [[ -e $feed_destination || -L $feed_destination ]]; then
    [[ -f $release_feed_marker && -f $feed_destination && ! -L $feed_destination &&
       $(stat -c '%U:%G:%a:%h' "$feed_destination") == root:root:644:1 ]] || die "unmanaged or unsafe release-feed unit: $feed_unit"
  fi
done
if [[ -e $backup_broker_marker || -L $backup_broker_marker ]]; then
  [[ -f $backup_broker_marker && ! -L $backup_broker_marker &&
     $(stat -c '%U:%G:%a:%h' "$backup_broker_marker") == root:root:600:1 ]] || die 'Hub backup broker ownership marker is unsafe'
  cmp -s -- "$backup_broker_marker" <(printf 'SOVAGRID_HUB_BACKUP_BROKER_V1\n') || die 'Hub backup broker ownership marker is invalid'
fi
for backup_unit in sovagrid-hub-backup-control.service sovagrid-hub-backup-control.socket; do
  backup_destination=/etc/systemd/system/$backup_unit
  if [[ -e $backup_destination || -L $backup_destination ]]; then
    [[ -f $backup_broker_marker && -f $backup_destination && ! -L $backup_destination &&
       $(stat -c '%U:%G:%a:%h' "$backup_destination") == root:root:644:1 ]] || die "unmanaged or unsafe Hub backup unit: $backup_unit"
  fi
done
for web_agent_unit in sovagrid-web-agent-control.service sovagrid-web-agent-control.socket; do
  destination=/etc/systemd/system/$web_agent_unit
  if [[ -e $destination || -L $destination ]]; then
    [[ -f $web_agent_marker && -f $destination && ! -L $destination &&
       $(stat -c '%U:%G:%a:%h' "$destination") == root:root:644:1 ]] ||
      die "unmanaged or unsafe Web Agent unit: $web_agent_unit"
  fi
done
if (( with_wireguard )); then
  for unit in sovagrid-vpn-control.service sovagrid-vpn-control.socket; do
    if [[ -e /etc/systemd/system/$unit && ! -f /etc/sovagrid/.vpn-control-managed-by-run-sh ]]; then
      die "an unmanaged $unit already exists; inspect it before installing VPN control"
    fi
  done
fi
if (( with_terminal )); then
  for unit in sovagrid-terminal-control.service sovagrid-terminal-control.socket; do
    if [[ -e /etc/systemd/system/$unit && ! -f /etc/sovagrid/.terminal-unit-managed-by-run-sh ]]; then
      die "an unmanaged $unit already exists; inspect it before installing the PTY broker"
    fi
  done
fi
if (( with_journal )); then
  if [[ -e /etc/sovagrid/.journal-managed-by-run-sh || -L /etc/sovagrid/.journal-managed-by-run-sh ]]; then
    [[ -f /etc/sovagrid/.journal-managed-by-run-sh && ! -L /etc/sovagrid/.journal-managed-by-run-sh &&
       $(stat -c '%U:%G:%a' /etc/sovagrid/.journal-managed-by-run-sh) == root:root:600 ]] || die 'journal install marker is unsafe'
  fi
  for unit in sovagrid-journal-control.service sovagrid-journal-control.socket; do
    if [[ ( -e /etc/systemd/system/$unit || -L /etc/systemd/system/$unit ) &&
          ! -f /etc/sovagrid/.journal-managed-by-run-sh ]]; then
      die "an unmanaged $unit already exists; inspect it before installing the journal broker"
    fi
  done
  if [[ ( -e /etc/sovagrid-journal/units.json || -L /etc/sovagrid-journal/units.json ) &&
        ! -f /etc/sovagrid/.journal-managed-by-run-sh ]]; then
    die 'an unmanaged journal policy already exists; inspect it before installing the journal broker'
  fi
fi
if (( with_containers || containers_disable_requested )); then
  if [[ -e /etc/sovagrid/.containers-managed-by-run-sh || -L /etc/sovagrid/.containers-managed-by-run-sh ]]; then
    [[ -f /etc/sovagrid/.containers-managed-by-run-sh && ! -L /etc/sovagrid/.containers-managed-by-run-sh &&
       $(stat -c '%U:%G:%a' /etc/sovagrid/.containers-managed-by-run-sh) == root:root:600 ]] || die 'container inventory marker is unsafe'
  fi
  for container_unit in sovagrid-container-inventory.service sovagrid-container-inventory.timer; do
    if [[ -e /etc/systemd/system/$container_unit || -L /etc/systemd/system/$container_unit ]]; then
      [[ -f /etc/sovagrid/.containers-managed-by-run-sh && ! -L /etc/sovagrid/.containers-managed-by-run-sh ]] || die "an unmanaged $container_unit already exists"
      [[ -f /etc/systemd/system/$container_unit && ! -L /etc/systemd/system/$container_unit &&
         $(stat -c '%U:%G:%a' "/etc/systemd/system/$container_unit") == root:root:644 ]] || die "$container_unit is unsafe"
    fi
  done
  if [[ -e /var/lib/sovagrid-containers || -L /var/lib/sovagrid-containers ]]; then
    [[ -d /var/lib/sovagrid-containers && ! -L /var/lib/sovagrid-containers &&
       -f /etc/sovagrid/.containers-managed-by-run-sh ]] || die 'container inventory directory is unmanaged or unsafe'
  elif (( containers_disable_requested )) || [[ -f /etc/sovagrid/.containers-managed-by-run-sh ]]; then
    die 'managed container inventory directory is missing'
  fi
fi

blueprint_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source_root=$(dirname -- "$blueprint_dir")
compose_file="$blueprint_dir/deploy/compose.yaml"
telegram_file="$blueprint_dir/deploy/compose.telegram.yaml"
deploy_env=/etc/sovagrid/deploy.env
bot_token=/etc/sovagrid-hub/bot.token
admin_password=/etc/sovagrid/admin-password

apt_refreshed=0
apt_refresh() {
  if (( ! apt_refreshed )); then
    DEBIAN_FRONTEND=noninteractive apt-get update
    apt_refreshed=1
  fi
}

if ! command -v python3 >/dev/null 2>&1; then
  apt_refresh
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3
fi
python3 -c 'import sys; assert sys.version_info >= (3, 10), "Python 3.10+ is required"' || die 'Python 3.10+ is required'

if ! command -v docker >/dev/null 2>&1; then
  say 'installing Docker from Ubuntu packages'
  apt_refresh
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends docker.io
  systemctl enable --now docker
fi
docker info >/dev/null || die 'Docker daemon is unavailable; existing containers were not changed'

if ! docker compose version >/dev/null 2>&1; then
  say 'installing the Docker Compose plugin'
  apt_refresh
  if apt-cache show docker-compose-v2 >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends docker-compose-v2
  elif apt-cache show docker-compose-plugin >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends docker-compose-plugin
  else
    die 'no Compose plugin package is available in configured APT repositories'
  fi
fi
docker compose version >/dev/null || die 'Docker Compose is unavailable'

for repo in sovagrid-hub sovagrid-web sovagrid-agent sovagrid-vpn; do
  path="$source_root/$repo"
  [[ ! -L $path ]] || die "$path is a symlink; use a real checkout"
  if [[ ! -d $path ]]; then
    [[ ${SOVAGRID_FETCH_MISSING:-0} == 1 ]] || die "missing $path; place the repos beside sovagrid-blueprint or set SOVAGRID_FETCH_MISSING=1"
    github_owner=${SOVAGRID_GITHUB_OWNER:-sovagrid}
    [[ $github_owner =~ ^[A-Za-z0-9-]+$ ]] || die 'invalid GitHub owner name'
    if ! command -v git >/dev/null 2>&1; then
      apt_refresh
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends git
    fi
    say "cloning $repo from GitHub over HTTPS"
    git clone -- "https://github.com/${github_owner}/${repo}.git" "$path"
  fi
done
[[ -f $source_root/sovagrid-hub/Dockerfile && -f $source_root/sovagrid-web/Dockerfile ]] || die 'Hub or Web Dockerfile is missing'
[[ -f $source_root/sovagrid-agent/deploy/sovagrid-agent.service ]] || die 'Agent systemd unit is missing'
if (( with_terminal )); then
  for unit in sovagrid-terminal-control.service sovagrid-terminal-control.socket; do
    [[ -f $source_root/sovagrid-agent/deploy/$unit && ! -L $source_root/sovagrid-agent/deploy/$unit ]] || die "terminal broker $unit is missing"
  done
fi
if (( with_journal )); then
  for source_file in sovagrid_agent/journal_broker.py deploy/sovagrid-journal-control.service deploy/sovagrid-journal-control.socket; do
    [[ -f $source_root/sovagrid-agent/$source_file && ! -L $source_root/sovagrid-agent/$source_file ]] || die "journal broker source $source_file is missing or a symlink"
  done
fi
if (( with_containers )); then
  for source_file in sovagrid_agent/containers.py sovagrid_agent/container_collector.py deploy/sovagrid-container-inventory.service deploy/sovagrid-container-inventory.timer; do
    [[ -f $source_root/sovagrid-agent/$source_file && ! -L $source_root/sovagrid-agent/$source_file ]] || die "container inventory source $source_file is missing or a symlink"
  done
  for code_dir in /opt/sovagrid-agent /opt/sovagrid-agent/sovagrid_agent; do
    if [[ -e $code_dir || -L $code_dir ]]; then
      [[ -d $code_dir && ! -L $code_dir && $(stat -c '%U:%G:%a' "$code_dir") == root:root:755 ]] || die "collector code directory is unsafe: $code_dir"
    fi
  done
fi
[[ -f $source_root/sovagrid-vpn/deploy/sovagrid-vpn-status.service && -f $source_root/sovagrid-vpn/deploy/sovagrid-vpn-status.timer ]] || die 'VPN inventory systemd units are missing'
for auto_file in auto_update.py remote_update_worker.py sovagrid-auto-update.service sovagrid-auto-update.timer \
                 release_feed.py sovagrid-release-feed.service sovagrid-release-feed.timer \
                 sovagrid-hub-backup-control.socket sovagrid-hub-backup-control.service compose.backup.yaml; do
  [[ -f $source_root/sovagrid-blueprint/deploy/$auto_file && ! -L $source_root/sovagrid-blueprint/deploy/$auto_file ]] || die "auto-update source $auto_file is missing or a symlink"
done
for web_agent_file in web_agent_bundle.py web_agent_jobs.py web_agent_local_rpc.py web_agent_target_ssh.py \
                      web_agent_service.py sovagrid-web-agent-control.socket \
                      sovagrid-web-agent-control.service compose.web-agent.yaml; do
  [[ -f $source_root/sovagrid-blueprint/deploy/$web_agent_file &&
     ! -L $source_root/sovagrid-blueprint/deploy/$web_agent_file ]] ||
    die "Web Agent source $web_agent_file is missing or a symlink"
done
if [[ $source_root != /opt/sovagrid-src ]]; then
  [[ ! -e $web_agent_marker && ! -L $web_agent_marker ]] ||
    die 'managed Web Agent installer requires /opt/sovagrid-src'
  web_agent_deferred=1
elif [[ ! -f $source_root/sovagrid-bundle.json || -L $source_root/sovagrid-bundle.json ]]; then
  [[ ! -e $web_agent_marker && ! -L $web_agent_marker ]] ||
    die 'managed Web Agent installer lost its source manifest'
  web_agent_deferred=1
fi
if (( ! backup_broker_deferred )) && [[ $source_root != /opt/sovagrid-src ]]; then
  [[ ! -e $backup_broker_marker && ! -L $backup_broker_marker ]] || die 'managed Hub backup broker requires /opt/sovagrid-src'
  backup_broker_deferred=1
fi
# Browser SSH issues its grant through the managed Hub Compose path. A
# checkout elsewhere may still build Hub/Web for testing, but cannot start a
# gateway that would silently target a different installation.
if [[ $source_root != /opt/sovagrid-src ]]; then
  [[ ! -e $ssh_gateway_marker && ! -L $ssh_gateway_marker ]] ||
    die 'managed SSH gateway requires /opt/sovagrid-src'
  ssh_gateway_deferred=1
fi
if (( ! ssh_gateway_deferred )); then
  for source_file in Dockerfile.ssh-gateway gateway/package.json gateway/package-lock.json gateway/server.js; do
    [[ -f $source_root/sovagrid-web/$source_file && ! -L $source_root/sovagrid-web/$source_file ]] ||
      die "SSH gateway source is missing or unsafe: $source_file"
  done
  [[ -f $source_root/sovagrid-web/deploy/Caddyfile.container &&
     ! -L $source_root/sovagrid-web/deploy/Caddyfile.container ]] ||
    die 'SSH gateway Caddy route source is missing or unsafe'
  grep -Fq '@browser_ssh path /api/v1/browser-ssh/*' \
    "$source_root/sovagrid-web/deploy/Caddyfile.container" ||
    die 'SSH gateway Caddy route is missing'
fi
# An independently updated Blueprint can be paired with an older, verified
# Hub source that predates the restricted broker. Keep that upgrade usable;
# the broker is installed once a compatible Hub arrives.
if (( ! backup_broker_deferred )) &&
   [[ -L $source_root/sovagrid-hub/sovagrid_hub/backup_broker.py ]]; then
  die 'Hub backup broker source is a symlink'
fi
if (( ! backup_broker_deferred )) &&
   [[ ! -f $source_root/sovagrid-hub/sovagrid_hub/backup_broker.py ]]; then
  [[ ! -e $backup_broker_marker && ! -L $backup_broker_marker ]] || die 'managed Hub backup broker source is missing'
  backup_broker_deferred=1
fi
systemd-analyze verify "$source_root/sovagrid-blueprint/deploy/sovagrid-release-feed.service" \
                       "$source_root/sovagrid-blueprint/deploy/sovagrid-release-feed.timer" || die 'release-feed systemd units are invalid'
if [[ -e /etc/sovagrid/release-feed.json || -L /etc/sovagrid/release-feed.json ]]; then
  python3 -I "$source_root/sovagrid-blueprint/deploy/release_feed.py" status >/dev/null || die 'release-feed opt-in state is unsafe'
fi

install_release_feed_units() {
  if (( release_feed_deferred )); then
    say 'signed release discovery installation deferred until its rollback snapshot is available'
    return
  fi
  local feed_source feed_unit feed_destination feed_temporary
  if [[ ! -f $release_feed_marker ]]; then
    feed_temporary=$(mktemp "$release_feed_marker.XXXXXXXX")
    printf 'SOVAGRID_RELEASE_FEED_UNITS_V1\n' > "$feed_temporary"
    chown root:root "$feed_temporary"
    chmod 0600 "$feed_temporary"
    mv -Tf -- "$feed_temporary" "$release_feed_marker"
  fi
  for feed_unit in sovagrid-release-feed.service sovagrid-release-feed.timer; do
    feed_source="$source_root/sovagrid-blueprint/deploy/$feed_unit"
    feed_destination="/etc/systemd/system/$feed_unit"
    feed_temporary=$(mktemp "$feed_destination.XXXXXXXX")
    if ! install -o root -g root -m 0644 "$feed_source" "$feed_temporary" ||
       ! mv -Tf -- "$feed_temporary" "$feed_destination"; then
      rm -f -- "$feed_temporary"
      die "release-feed unit $feed_unit could not be installed"
    fi
  done
  systemctl daemon-reload
  if [[ ! -e /etc/sovagrid/release-feed.json && ! -L /etc/sovagrid/release-feed.json ]]; then
    systemctl disable --now sovagrid-release-feed.timer || die 'release-feed timer could not be disabled'
    ! systemctl is-active --quiet sovagrid-release-feed.timer || die 'release-feed timer unexpectedly remained active'
  else
    systemctl is-enabled --quiet sovagrid-release-feed.timer || die 'opted-in release-feed timer is not enabled'
    systemctl is-active --quiet sovagrid-release-feed.timer || die 'opted-in release-feed timer is not active'
  fi
  say 'signed release discovery units installed; subscription requires explicit enable in the client'
}

install_backup_broker() {
  if (( backup_broker_deferred )); then
    say 'Hub backup browser access deferred until a managed source and rollback snapshot are available'
    return
  fi
  local path unit source destination temporary
  [[ -f $source_root/sovagrid-hub/sovagrid_hub/backup_broker.py &&
     ! -L $source_root/sovagrid-hub/sovagrid_hub/backup_broker.py ]] || die 'Hub backup broker source is missing or a symlink'
  for path in /opt "$source_root" "$source_root/sovagrid-hub"; do
    [[ -d $path && ! -L $path && $(stat -c '%u' "$path") == 0 &&
       -z $(find "$path" -maxdepth 0 -perm /022 -print -quit) ]] || die "Hub backup broker code ancestor is writable or untrusted: $path"
  done
  [[ -z $(find "$source_root/sovagrid-hub/sovagrid_hub" \
                \( ! -user root -o -perm /022 -o \( ! -type f -a ! -type d \) \) \
                -print -quit) ]] || die 'Hub backup broker Python package must contain only root-owned, non-writable files and directories'
  for path in /opt/sovagrid-candidates /var/lib/sovagrid/backups \
              /var/lib/sovagrid-host-backup-operations; do
    if [[ -e $path || -L $path ]]; then
      [[ -d $path && ! -L $path && $(stat -c '%U:%G:%a' "$path") == root:root:700 ]] || die "unsafe Hub backup directory: $path"
    else
      install -d -o root -g root -m 0700 "$path"
    fi
  done
  if [[ -e /var/lib/sovagrid/backups/.broker-requests || -L /var/lib/sovagrid/backups/.broker-requests ]]; then
    [[ -f $backup_broker_marker && -d /var/lib/sovagrid/backups/.broker-requests &&
       ! -L /var/lib/sovagrid/backups/.broker-requests &&
       $(stat -c '%U:%G:%a' /var/lib/sovagrid/backups/.broker-requests) == root:root:700 ]] || die 'Hub backup request ledger is unmanaged or unsafe'
  fi
  systemd-analyze verify "$blueprint_dir/deploy/sovagrid-hub-backup-control.socket" \
                         "$blueprint_dir/deploy/sovagrid-hub-backup-control.service" || die 'Hub backup broker systemd units are invalid'
  if [[ ! -f $backup_broker_marker ]]; then
    temporary=$(mktemp "$backup_broker_marker.XXXXXXXX")
    printf 'SOVAGRID_HUB_BACKUP_BROKER_V1\n' > "$temporary"
    chown root:root "$temporary"
    chmod 0600 "$temporary"
    mv -Tf -- "$temporary" "$backup_broker_marker"
  fi
  for unit in sovagrid-hub-backup-control.socket sovagrid-hub-backup-control.service; do
    source="$blueprint_dir/deploy/$unit"
    destination="/etc/systemd/system/$unit"
    temporary=$(mktemp "$destination.XXXXXXXX")
    if ! install -o root -g root -m 0644 "$source" "$temporary" ||
       ! mv -Tf -- "$temporary" "$destination"; then
      rm -f -- "$temporary"
      die "Hub backup broker unit $unit could not be installed"
    fi
  done
  systemctl daemon-reload
  systemctl enable --now sovagrid-hub-backup-control.socket || die 'Hub backup socket could not start'
  systemctl restart sovagrid-hub-backup-control.service || die 'Hub backup broker could not start'
  systemctl is-active --quiet sovagrid-hub-backup-control.socket || die 'Hub backup socket is inactive'
  systemctl is-active --quiet sovagrid-hub-backup-control.service || die 'Hub backup broker is inactive'
  [[ -S /run/sovagrid-hub-backup/control.sock && ! -L /run/sovagrid-hub-backup/control.sock &&
     $(stat -c '%U:%G:%a' /run/sovagrid-hub-backup/control.sock) == root:sovagrid-hub:660 ]] || die 'Hub backup socket has unsafe permissions'
  say 'restricted Hub backup broker is ready'
}

install_web_agent_service() {
  if (( web_agent_deferred )); then
    say 'Web Agent installation waits for a managed source and rollback snapshot'
    return
  fi
  local unit source destination temporary
  [[ $source_root == /opt/sovagrid-src && -f $source_root/sovagrid-bundle.json &&
     ! -L $source_root/sovagrid-bundle.json ]] ||
    die 'Web Agent installation requires the verified managed source bundle'
  for source in /opt /opt/sovagrid-src "$blueprint_dir" "$blueprint_dir/deploy"; do
    [[ -d $source && ! -L $source && $(stat -c '%u' "$source") == 0 &&
       -z $(find "$source" -maxdepth 0 -perm /022 -print -quit) ]] ||
      die "Web Agent source ancestor is writable or untrusted: $source"
  done
  if [[ -e /var/lib/sovagrid/web-agent || -L /var/lib/sovagrid/web-agent ]]; then
    [[ -d /var/lib/sovagrid/web-agent && ! -L /var/lib/sovagrid/web-agent &&
       $(stat -c '%U:%G:%a' /var/lib/sovagrid/web-agent) == root:root:700 ]] ||
      die 'Web Agent private directory is unsafe'
  else
    install -d -o root -g root -m 0700 /var/lib/sovagrid/web-agent
  fi
  if [[ ! -f $web_agent_marker ]]; then
    temporary=$(mktemp "$web_agent_marker.XXXXXXXX")
    printf 'SOVAGRID_WEB_AGENT_INSTALL_V1\n' > "$temporary"
    chown root:root "$temporary"
    chmod 0600 "$temporary"
    mv -Tf -- "$temporary" "$web_agent_marker"
  fi
  systemd-analyze verify "$blueprint_dir/deploy/sovagrid-web-agent-control.socket" \
                         "$blueprint_dir/deploy/sovagrid-web-agent-control.service" ||
    die 'Web Agent systemd units are invalid'
  for unit in sovagrid-web-agent-control.socket sovagrid-web-agent-control.service; do
    source="$blueprint_dir/deploy/$unit"
    destination="/etc/systemd/system/$unit"
    temporary=$(mktemp "$destination.XXXXXXXX")
    if ! install -o root -g root -m 0644 "$source" "$temporary" ||
       ! mv -Tf -- "$temporary" "$destination"; then
      rm -f -- "$temporary"
      die "Web Agent unit $unit could not be installed"
    fi
  done
  systemctl daemon-reload
  systemctl enable --now sovagrid-web-agent-control.socket ||
    die 'Web Agent socket could not start'
  systemctl restart sovagrid-web-agent-control.service ||
    die 'Web Agent service could not start'
  systemctl is-active --quiet sovagrid-web-agent-control.socket ||
    die 'Web Agent socket is inactive'
  systemctl is-active --quiet sovagrid-web-agent-control.service ||
    die 'Web Agent service is inactive'
  [[ -S /run/sovagrid-web-agent/control.sock && ! -L /run/sovagrid-web-agent/control.sock &&
     $(stat -c '%U:%G:%a' /run/sovagrid-web-agent/control.sock) == root:sovagrid-web-agent:660 ]] ||
    die 'Web Agent socket has unsafe permissions'
  say 'Web Agent installer is ready for reviewed SSH enrollment'
}

reserve_identity() {
  local name=$1 uid=$2
  local existing
  existing=$(getent passwd "$uid" | cut -d: -f1 || true)
  [[ -z $existing || $existing == "$name" ]] || die "UID $uid belongs to $existing"
  existing=$(getent group "$uid" | cut -d: -f1 || true)
  [[ -z $existing || $existing == "$name" ]] || die "GID $uid belongs to $existing"
  if getent group "$name" >/dev/null; then
    [[ $(getent group "$name" | cut -d: -f3) == "$uid" ]] || die "$name group has a different GID"
  else
    groupadd --system --gid "$uid" "$name"
  fi
  if getent passwd "$name" >/dev/null; then
    [[ $(id -u "$name") == "$uid" ]] || die "$name user has a different UID"
    [[ $(id -g "$name") == "$uid" ]] || die "$name user has a different primary GID"
  else
    useradd --system --uid "$uid" --gid "$uid" --home-dir /nonexistent --shell /usr/sbin/nologin "$name"
  fi
}
reserve_identity sovagrid-hub 10001
reserve_identity sovagrid-web 10002
if (( ! web_agent_deferred )); then
  existing_web_agent_group=$(getent group 10005 | cut -d: -f1 || true)
  [[ -z $existing_web_agent_group || $existing_web_agent_group == sovagrid-web-agent ]] ||
    die 'GID 10005 is already assigned; cannot grant the SSH gateway Web Agent access'
  if getent group sovagrid-web-agent >/dev/null; then
    [[ $(getent group sovagrid-web-agent | cut -d: -f3) == 10005 ]] ||
      die 'sovagrid-web-agent group has a different GID'
  else
    groupadd --system --gid 10005 sovagrid-web-agent
  fi
fi
if (( with_terminal )); then
  reserve_identity sovagrid-shell 10003
  [[ $(id -nG sovagrid-shell) == sovagrid-shell ]] || die 'sovagrid-shell must not have supplementary groups'
fi
if (( with_journal )); then
  reserve_identity sovagrid-journal 10004
  getent group systemd-journal >/dev/null || die 'systemd-journal group is unavailable on this host'
fi

if ! getent group sovagrid >/dev/null; then groupadd --system sovagrid; fi
if getent passwd sovagrid >/dev/null; then
  [[ $(id -u sovagrid) != 0 ]] || die 'sovagrid Agent user must not be root'
  [[ $(id -gn sovagrid) == sovagrid ]] || die 'sovagrid Agent user has an unexpected primary group'
else
  useradd --system --gid sovagrid --home-dir /var/lib/sovagrid-agent --shell /usr/sbin/nologin sovagrid
fi
if (( with_journal )); then
  for broad_group in systemd-journal adm; do
    if id -nG sovagrid | tr ' ' '\n' | grep -Fxq "$broad_group"; then
      die "Agent user already has broad $broad_group access; remove it before enabling the narrow journal broker"
    fi
  done
fi
if (( with_containers )); then
  getent group docker >/dev/null || die 'Docker socket group is unavailable for the isolated container collector'
  for broad_group in docker podman; do
    if id -nG sovagrid | tr ' ' '\n' | grep -Fxq "$broad_group"; then
      die "Agent user already has broad $broad_group access; container inventory requires a separate root collector"
    fi
  done
fi

install -d -o root -g root -m 0700 /var/lib/sovagrid
install -d -o sovagrid-hub -g sovagrid-hub -m 0700 /var/lib/sovagrid/hub
install -d -o root -g sovagrid-hub -m 0750 /var/lib/sovagrid/vpn
install -d -o sovagrid-web -g sovagrid-web -m 0700 /var/lib/sovagrid/caddy
install -d -o root -g sovagrid -m 0750 /etc/sovagrid
install -d -o root -g sovagrid-hub -m 0750 /etc/sovagrid-hub
[[ ! -L /var/lib/sovagrid-agent ]] || die 'Agent data directory must not be a symlink'
if (( ! hub_only )); then
  install -d -o sovagrid -g sovagrid -m 0700 /var/lib/sovagrid-agent
fi
if (( files_requested )); then
  [[ ! -L /var/lib/sovagrid-agent/files ]] || die 'Agent file root must not be a symlink'
  install -d -o sovagrid -g sovagrid -m 0700 /var/lib/sovagrid-agent/files
  [[ $(stat -c '%U:%G:%a' /var/lib/sovagrid-agent/files) == sovagrid:sovagrid:700 ]] || die 'Agent file root has unsafe ownership or mode'
fi
if (( with_terminal )); then
  install -d -o sovagrid-shell -g sovagrid-shell -m 0700 /var/lib/sovagrid-shell
fi
if (( with_journal )); then
  if [[ -e /etc/sovagrid-journal || -L /etc/sovagrid-journal ]]; then
    [[ -d /etc/sovagrid-journal && ! -L /etc/sovagrid-journal ]] || die 'journal policy directory must be a real directory'
    [[ -f /etc/sovagrid/.journal-managed-by-run-sh ]] || die 'an unmanaged journal policy directory already exists'
    [[ $(stat -c '%U:%G:%a' /etc/sovagrid-journal) == root:sovagrid-journal:750 ]] || die 'journal policy directory has unsafe ownership or mode'
  elif [[ -f /etc/sovagrid/.journal-managed-by-run-sh ]]; then
    die 'managed journal policy directory is missing'
  fi
  install -d -o root -g sovagrid-journal -m 0750 /etc/sovagrid-journal
  [[ $(stat -c '%U:%G:%a' /etc/sovagrid-journal) == root:sovagrid-journal:750 ]] || die 'journal policy directory has unsafe ownership or mode'
fi
if (( with_containers || containers_disable_requested )); then
  if [[ -e /var/lib/sovagrid-containers || -L /var/lib/sovagrid-containers ]]; then
    [[ $(stat -c '%U:%G:%a' /var/lib/sovagrid-containers) == root:sovagrid:750 ]] || die 'container inventory directory has unsafe ownership or mode'
    [[ -z $(find /var/lib/sovagrid-containers -mindepth 1 -maxdepth 1 ! -name snapshot.json -print -quit) ]] || die 'container inventory directory has unexpected files'
    if [[ -e /var/lib/sovagrid-containers/snapshot.json || -L /var/lib/sovagrid-containers/snapshot.json ]]; then
      [[ -f /var/lib/sovagrid-containers/snapshot.json && ! -L /var/lib/sovagrid-containers/snapshot.json &&
         $(stat -c '%U:%G:%a:%h' /var/lib/sovagrid-containers/snapshot.json) == root:sovagrid:640:1 ]] || die 'container inventory snapshot is unsafe'
    fi
  fi
  if (( with_containers )); then
    install -d -o root -g sovagrid -m 0750 /var/lib/sovagrid-containers
  fi
fi
if (( ! hub_only )); then
  install -d -o root -g root -m 0755 /opt/sovagrid-agent
  install -d -o root -g root -m 0755 /opt/sovagrid-agent/sovagrid_agent
  if (( with_containers )); then
    [[ $(stat -c '%U:%G:%a' /opt/sovagrid-agent) == root:root:755 &&
       $(stat -c '%U:%G:%a' /opt/sovagrid-agent/sovagrid_agent) == root:root:755 ]] || die 'collector code directory must be root-owned mode 0755'
  fi
fi

[[ ! -L $deploy_env ]] || die "$deploy_env must not be a symlink"
if [[ ! -f $deploy_env ]]; then
  cat > "$deploy_env" <<'ENV'
SOVAGRID_HUB_DATA_DIR=/var/lib/sovagrid/hub
SOVAGRID_CADDY_DATA_DIR=/var/lib/sovagrid/caddy
ENV
fi
chown root:root "$deploy_env"
chmod 0600 "$deploy_env"
grep -Fxq 'SOVAGRID_HUB_DATA_DIR=/var/lib/sovagrid/hub' "$deploy_env" || die 'unexpected Hub data path in deploy.env'
grep -Fxq 'SOVAGRID_CADDY_DATA_DIR=/var/lib/sovagrid/caddy' "$deploy_env" || die 'unexpected Caddy data path in deploy.env'
SOVAGRID_HUB_DATA_DIR=/var/lib/sovagrid/hub
SOVAGRID_CADDY_DATA_DIR=/var/lib/sovagrid/caddy
export SOVAGRID_HUB_DATA_DIR SOVAGRID_CADDY_DATA_DIR

compose=(docker compose --env-file "$deploy_env" -f "$compose_file")
# Manual installer runs take the same candidate lock as backup create, full
# update and offline restore. Keep lock order candidate -> public Web.
if (( ! backup_broker_deferred )) && [[ ${SOVAGRID_PUBLIC_WEB_LOCK_HELD:-0} != 1 ]]; then
  candidate_root=/opt/sovagrid-candidates
  if [[ -e $candidate_root || -L $candidate_root ]]; then
    [[ -d $candidate_root && ! -L $candidate_root &&
       $(stat -c '%U:%G:%a' "$candidate_root") == root:root:700 ]] || die 'unsafe candidate directory for Hub backups'
  else
    install -d -o root -g root -m 0700 "$candidate_root"
  fi
  [[ ! -L $candidate_root/.lock ]] || die 'unsafe candidate lock for Hub backups'
  # A lock inherited from another installer must retain its original mode;
  # create only a missing lock with explicit permissions before opening it.
  if [[ ! -e $candidate_root/.lock ]]; then
    install -o root -g root -m 0600 /dev/null "$candidate_root/.lock"
  fi
  exec 9>>"$candidate_root/.lock"
  candidate_lock_metadata=$(stat -c '%u:%g:%a:%h' -- "$candidate_root/.lock") || die 'cannot inspect candidate lock for Hub backups'
  [[ -f $candidate_root/.lock && $candidate_lock_metadata == 0:0:600:1 ]] || die "unsafe candidate lock for Hub backups ($candidate_lock_metadata)"
  flock -x -w 180 9 || die 'another SovaGrid update, restore or backup is running'
fi
# Serialize manual installs/feature changes with public HTTPS and GUI updates.
# The pinned GUI updater already owns this lock in its supervising process.
if [[ ${SOVAGRID_PUBLIC_WEB_LOCK_HELD:-0} != 1 ]]; then
  public_lock=/var/lib/sovagrid/.public-web.lock
  [[ ! -L $public_lock ]] || die 'public Web lock is unsafe'
  if [[ ! -e $public_lock ]]; then
    install -o root -g root -m 0600 /dev/null "$public_lock"
  fi
  exec 8>>"$public_lock"
  [[ -f $public_lock && $(stat -c '%u:%a' "$public_lock") == 0:600 ]] || die 'public Web lock is unsafe'
  flock -x -w 180 8 || die 'another SovaGrid configuration operation is running'
fi
# Bind the image to the verified source only after acquiring the same locks
# that serialize source replacement by an updater. The locks remain held while
# Compose builds and starts the Hub, so its embedded digest describes its code.
SOVAGRID_BUNDLE_MANIFEST_SHA256=
if [[ -e $source_root/sovagrid-bundle.json || -L $source_root/sovagrid-bundle.json ]]; then
  [[ -f $source_root/sovagrid-bundle.json && ! -L $source_root/sovagrid-bundle.json ]] ||
    die 'source bundle manifest is unsafe'
  SOVAGRID_BUNDLE_MANIFEST_SHA256=$(python3 -B -I - "$source_root" "$blueprint_dir/deploy/remote_update_worker.py" <<'PY'
import importlib.util
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location("sovagrid_verified_source", sys.argv[2])
if spec is None or spec.loader is None:
    raise SystemExit("source manifest verifier is unavailable")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
digest, _ = module.source_manifest(Path(sys.argv[1]), allow_generated=True)
print(digest)
PY
  ) || die 'source bundle manifest could not be verified'
  [[ $SOVAGRID_BUNDLE_MANIFEST_SHA256 =~ ^[0-9a-f]{64}$ ]] ||
    die 'source bundle manifest digest is invalid'
fi
export SOVAGRID_BUNDLE_MANIFEST_SHA256

public_overlay=''
if [[ -e /etc/sovagrid/public-web || -L /etc/sovagrid/public-web ]]; then
  [[ $source_root == /opt/sovagrid-src ]] || die 'public Web updates require the managed /opt/sovagrid-src source tree'
  # The helper validates ownership, generation hashes and full source manifest.
  # Refuse unsafe state instead of silently dropping HTTPS during an update.
  [[ -f $blueprint_dir/deploy/public_web.py && ! -L $blueprint_dir/deploy/public_web.py ]] || die 'public Web support is missing'
  public_overlay=$(python3 -B -I "$blueprint_dir/deploy/public_web.py" compose-overlay) || die 'public Web settings are unsafe; existing containers were not changed'
  if [[ -n $public_overlay ]]; then
    [[ $public_overlay =~ ^/etc/sovagrid/public-web/generations/[0-9a-f]{32}/compose\.yaml$ ]] || die 'unexpected public Web overlay path'
    compose+=(-f "$public_overlay")
  fi
fi
local_overlay=''
if [[ -e /etc/sovagrid/local-web || -L /etc/sovagrid/local-web ]]; then
  [[ $source_root == /opt/sovagrid-src ]] || die 'local Web updates require the managed /opt/sovagrid-src source tree'
  [[ -f $blueprint_dir/deploy/local_web.py && ! -L $blueprint_dir/deploy/local_web.py ]] || die 'local Web support is missing'
  local_overlay=$(python3 -B -I "$blueprint_dir/deploy/local_web.py" compose-overlay) ||
    die 'local Web settings are unsafe; existing containers were not changed'
  if [[ -n $local_overlay ]]; then
    [[ -z $public_overlay ]] || die 'public and local-only Web settings cannot both own the panel route'
    [[ $local_overlay =~ ^/etc/sovagrid/local-web/generations/[0-9a-f]{32}/compose\.yaml$ ]] ||
      die 'unexpected local Web overlay path'
    compose+=(-f "$local_overlay")
  fi
fi
install_backup_broker
if (( ! backup_broker_deferred )); then
  compose+=(-f "$blueprint_dir/deploy/compose.backup.yaml")
fi
if (( ! web_agent_deferred )); then
  compose+=(-f "$blueprint_dir/deploy/compose.web-agent.yaml")
fi
if [[ -f $bot_token ]]; then
  [[ ! -L $bot_token && -s $bot_token ]] || die 'Telegram token file must be nonempty and not a symlink'
  chown root:sovagrid-hub "$bot_token"
  chmod 0640 "$bot_token"
  export SOVAGRID_BOT_TOKEN_FILE="$bot_token"
  compose+=(-f "$telegram_file")
  say 'Telegram bot token found; enabling bot integration'
fi

# The project name is fixed. Refuse to take over another deployment using it.
if [[ ! -f /var/lib/sovagrid/.managed-by-run-sh ]]; then
  if [[ -n $(docker ps -a --filter label=com.docker.compose.project=sovagrid --format '{{.ID}}') ]]; then
    die 'an existing Docker Compose project named sovagrid is present; inspect it before continuing'
  fi
  if ss -H -ltn '( sport = :8766 or sport = :8767 )' | grep -q .; then
    die 'loopback ports 8766 or 8767 are occupied; no containers were changed'
  fi
fi

"${compose[@]}" config --quiet

if [[ ! -f /var/lib/sovagrid/hub/hub.sqlite ]]; then
  if [[ ! -e $admin_password ]]; then
    python3 - "$admin_password" <<'PY'
import os, secrets, sys
path = sys.argv[1]
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(path, flags, 0o600)
try:
    os.fchown(fd, 0, 0)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(secrets.token_urlsafe(32) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
except Exception:
    os.unlink(path)
    raise
PY
    say "generated a strong Hub admin password in $admin_password (root-only)"
  fi
  [[ -f $admin_password && ! -L $admin_password ]] || die 'admin password must be a regular file, not a symlink'
  [[ $(stat -c '%u:%a' "$admin_password") == 0:600 ]] || die 'admin password must be root-owned, mode 0600'
  python3 - "$source_root/sovagrid-hub" "$admin_password" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from sovagrid_hub.store import Store
password = Path(sys.argv[2]).read_text(encoding="utf-8").rstrip("\n")
Store("/var/lib/sovagrid/hub/hub.sqlite").initialize("admin", password)
PY
  chown -R sovagrid-hub:sovagrid-hub /var/lib/sovagrid/hub
  say 'Hub admin account initialized; its password content was not passed through argv or the environment'
fi

touch /var/lib/sovagrid/.managed-by-run-sh
chmod 0600 /var/lib/sovagrid/.managed-by-run-sh
install_web_agent_service
[[ -f $blueprint_dir/deploy/refresh_build_contexts.py && ! -L $blueprint_dir/deploy/refresh_build_contexts.py ]] || die 'build context metadata helper is missing or a symlink'
python3 "$blueprint_dir/deploy/refresh_build_contexts.py" "$source_root" || die 'build context metadata could not be refreshed'
if (( ssh_gateway_deferred )); then
  say 'building Hub and Web; SSH gateway waits for an updater with three-image rollback'
else
  say 'building and starting SovaGrid Hub, Web and SSH gateway'
fi
# A rebuilt OCI index may change while its image config and Compose service
# inputs stay identical. Replace stopped containers so final image-ID checks
# verify the newly selected build, rather than restarting an older container.
if (( ssh_gateway_deferred )); then
  "${compose[@]}" up -d --build --force-recreate hub web
else
  "${compose[@]}" up -d --build --force-recreate
fi

ca_source=/var/lib/sovagrid/caddy/caddy/pki/authorities/local/root.crt
for (( attempt=0; attempt<30; attempt++ )); do
  [[ -s $ca_source ]] && break
  sleep 1
done
[[ -s $ca_source ]] || die 'Caddy did not generate its local CA; inspect docker compose logs web'
if (( hub_only )); then
  # The existing external Agent may trust /etc/sovagrid/hub-ca.pem. Never
  # replace that CA with the new, independent local Hub's Caddy CA.
  ca_target=/var/lib/sovagrid/local-hub-ca.pem
  [[ ! -L $ca_target ]] || die 'local Hub CA path is unsafe'
  if [[ -e $ca_target ]]; then
    [[ -f $ca_target && $(stat -c '%U:%G:%a' "$ca_target") == root:root:600 ]] || die 'local Hub CA path is unsafe'
  fi
  install -o root -g root -m 0600 "$ca_source" "$ca_target"
else
  ca_target=/etc/sovagrid/hub-ca.pem
  install -o root -g root -m 0644 "$ca_source" "$ca_target"
fi
python3 - "$ca_target" <<'PY'
import ssl, sys, time, urllib.request
context = ssl.create_default_context(cafile=sys.argv[1])
for url, tls in (('http://127.0.0.1:8766/healthz', None),
                 ('https://localhost:8767/healthz', context)):
    for attempt in range(30):
        try:
            with urllib.request.urlopen(url, context=tls, timeout=5) as response:
                if response.status == 200:
                    break
        except (OSError, ssl.SSLError):
            pass
        if attempt == 29:
            raise SystemExit(f'SovaGrid health check did not become ready: {url}')
        time.sleep(1)
PY
if [[ -n $public_overlay ]]; then
  say 'Hub and Web health checks passed on loopback; existing public HTTPS was preserved'
else
  say 'Hub and Web health checks passed on loopback; no public ports were opened'
fi

if (( ! ssh_gateway_deferred )); then
  gateway_ready=0
  for (( attempt=0; attempt<30; attempt++ )); do
    gateway_ids=$(docker ps --filter label=com.docker.compose.project=sovagrid \
      --filter label=com.docker.compose.service=ssh-gateway --format '{{.ID}}')
    if [[ $gateway_ids =~ ^[0-9a-f]{12,64}$ ]] &&
       [[ $(docker inspect --format '{{.State.Health.Status}}' "$gateway_ids") == healthy ]]; then
      gateway_ready=1
      break
    fi
    sleep 1
  done
  if (( ! gateway_ready )); then
    "${compose[@]}" stop ssh-gateway || true
    die 'SSH gateway health check did not become ready'
  fi
  if (( ! web_agent_deferred )); then
    # Check the actual unprivileged container can reach the restricted host
    # socket. An invalid bearer must be rejected by the host worker itself.
    if ! docker exec "$gateway_ids" node -e '
const net = require("node:net");
const socket = net.createConnection("/run/sovagrid-web-agent/control.sock");
let text = "";
const timer = setTimeout(() => process.exit(1), 5000);
socket.on("error", () => process.exit(1));
socket.on("connect", () => socket.end(JSON.stringify({action:"list",session_token:"invalid",payload:{}})+"\n"));
socket.on("data", part => { text += part; if (text.length > 256) process.exit(1); });
socket.on("end", () => { clearTimeout(timer); try {
  const value = JSON.parse(text);
  process.exit(value.ok === false && value.error === "AUTH_REQUIRED" ? 0 : 1);
} catch { process.exit(1); } });
'; then
      "${compose[@]}" stop ssh-gateway || true
      die 'SSH gateway cannot reach the restricted Web Agent installer socket'
    fi
  fi
  # Container liveness is insufficient: the gateway must reach this host's
  # sshd through the fixed Docker bridge and the Web route must forward it.
  if ! python3 - <<'PY'
import json
import re
import time
import urllib.request

url = 'http://127.0.0.1:8766/api/v1/browser-ssh/host-key'
request = urllib.request.Request(
    url, data=b'{}', method='POST',
    headers={'Content-Type': 'application/json', 'Origin': 'http://127.0.0.1:8766'})
for attempt in range(5):
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            if response.status != 200:
                raise ValueError('unexpected response')
            raw = response.read(513)
        if len(raw) > 512:
            raise ValueError('oversized response')
        data = json.loads(raw)
        if (not isinstance(data, dict) or set(data) != {'protocol', 'port', 'key_type', 'fingerprint'} or
                data['protocol'] != 1 or type(data['port']) is not int or
                not 1 <= data['port'] <= 65535 or
                not isinstance(data['key_type'], str) or not data['key_type'] or
                not isinstance(data['fingerprint'], str) or
                re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', data['fingerprint']) is None):
            raise ValueError('invalid host key response')
        with urllib.request.urlopen('http://127.0.0.1:8766/sovagrid/monitoring/', timeout=5) as response:
            if response.status != 200 or not response.headers.get('Content-Type', '').startswith('text/html'):
                raise ValueError('panel route unavailable')
            page = response.read(262145)
        if len(page) > 262144 or b'id="sshLoginMode"' not in page or b'id="browserSshView"' not in page:
            raise ValueError('SSH-first panel missing')
        break
    except (OSError, ValueError, UnicodeError):
        if attempt == 4:
            raise SystemExit('browser SSH route cannot reach the host SSH service')
        time.sleep(1)
PY
  then
    "${compose[@]}" stop ssh-gateway || true
    die 'SSH gateway cannot verify this host SSH service; check sshd ListenAddress and SOVAGRID_HOST_SSH_PORT'
  fi
  if [[ -n $public_overlay ]]; then
    # SOVAGRID_PUBLIC_SSH_REFRESH_V1
    # The public Caddy site is an immutable, hash-checked generation. A new
    # Web image does not rewrite its old /api route: re-render it under the
    # lock already held by this installer or its supervising updater.
    SOVAGRID_PUBLIC_WEB_LOCK_HELD=1 python3 -B -I "$blueprint_dir/deploy/public_web.py" refresh >/dev/null ||
      die 'public HTTPS could not expose the browser SSH route; the previous site generation was restored'
    say 'public HTTPS now serves and verifies the browser SSH route'
  fi
  if [[ -n $local_overlay ]]; then
    SOVAGRID_PUBLIC_WEB_LOCK_HELD=1 python3 -B -I "$blueprint_dir/deploy/local_web.py" refresh >/dev/null ||
      die 'local panel route could not be refreshed; the previous generation was restored'
    say 'local panel route was verified through loopback without opening public ports'
  fi
  if [[ ! -e $ssh_gateway_marker ]]; then
    gateway_marker_temp=$(mktemp "$ssh_gateway_marker.XXXXXXXX")
    printf '%s\n' "$ssh_gateway_marker_content" >"$gateway_marker_temp"
    chown root:root "$gateway_marker_temp"
    chmod 0600 "$gateway_marker_temp"
    mv -Tf -- "$gateway_marker_temp" "$ssh_gateway_marker"
  fi
  say 'SSH gateway is healthy; password and key entry is available on this host'
fi

for directory in /opt /opt/sovagrid-vpn /opt/sovagrid-vpn/sovagrid_vpn; do
  [[ ! -L $directory ]] || die "$directory must not be a symlink"
done
install -d -o root -g root -m 0755 /opt/sovagrid-vpn/sovagrid_vpn
# Earlier read-only inventory installs kept the package root private. The
# unprivileged broker client now imports public code from this directory.
if [[ $(stat -c '%u:%a' /opt/sovagrid-vpn) == 0:700 ]]; then
  chmod 0755 /opt/sovagrid-vpn
fi
for directory in /opt /opt/sovagrid-vpn /opt/sovagrid-vpn/sovagrid_vpn; do
  [[ $(stat -c '%u:%a' "$directory") == 0:755 ]] || die "$directory must be root-owned mode 0755"
done
for file in "$source_root"/sovagrid-vpn/sovagrid_vpn/*.py; do
  destination="/opt/sovagrid-vpn/sovagrid_vpn/$(basename "$file")"
  temporary=$(mktemp "$destination.XXXXXXXX")
  install -o root -g root -m 0644 "$file" "$temporary"
  mv -Tf -- "$temporary" "$destination"
done
notice_repos=(sovagrid-vpn)
if (( ! hub_only )); then notice_repos+=(sovagrid-agent); fi
for repo in "${notice_repos[@]}"; do
  for notice in LICENSE ATTRIBUTION.md NOTICE; do
    file="$source_root/$repo/$notice"
    [[ -f $file && ! -L $file ]] || die "license notice is missing or a symlink: $repo/$notice"
    destination="/opt/$repo/$notice"
    temporary=$(mktemp "$destination.XXXXXXXX")
    install -o root -g root -m 0644 "$file" "$temporary"
    mv -Tf -- "$temporary" "$destination"
  done
done
install -o root -g root -m 0644 "$source_root/sovagrid-vpn/deploy/sovagrid-vpn-status.service" /etc/systemd/system/sovagrid-vpn-status.service
install -o root -g root -m 0644 "$source_root/sovagrid-vpn/deploy/sovagrid-vpn-status.timer" /etc/systemd/system/sovagrid-vpn-status.timer
touch /etc/sovagrid/.vpn-unit-managed-by-run-sh
chmod 0600 /etc/sovagrid/.vpn-unit-managed-by-run-sh
systemctl daemon-reload
systemctl enable --now sovagrid-vpn-status.timer
systemctl start sovagrid-vpn-status.service
[[ -s /var/lib/sovagrid/vpn/status.json ]] || die 'VPN inventory did not produce a snapshot'
say 'read-only VPN inventory is active; existing VPN containers were not changed'

if (( with_wireguard )); then
  [[ -f $source_root/sovagrid-vpn/deploy/install-wg-quick-apparmor.py ]] || die 'WireGuard AppArmor setup helper is missing'
  for required in sovagrid-vpn-ctl sovagrid-vpn-broker sovagrid-vpn-control.service sovagrid-vpn-control.socket; do
    [[ -f $source_root/sovagrid-vpn/deploy/$required && ! -L $source_root/sovagrid-vpn/deploy/$required ]] || die "VPN control source $required is missing or a symlink"
  done
  if ! command -v wg >/dev/null 2>&1 || ! command -v wg-quick >/dev/null 2>&1 || ! command -v ip >/dev/null 2>&1; then
    apt_refresh
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends wireguard-tools iproute2
  fi
  if ! /usr/bin/python3 -I -c 'import cryptography' >/dev/null 2>&1; then
    apt_refresh
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3-cryptography
  fi
  /usr/bin/python3 -I -c 'import cryptography' >/dev/null 2>&1 || die 'Python cryptography is required for sealed client-profile export'
  if [[ -f /etc/apparmor.d/wg-quick ]]; then
    python3 "$source_root/sovagrid-vpn/deploy/install-wg-quick-apparmor.py"
  fi
  for directory in /var/lib/sovagrid-vpn /etc/wireguard; do
    [[ ! -L $directory ]] || die "$directory must not be a symlink"
    if [[ ! -e $directory ]]; then install -d -o root -g root -m 0700 "$directory"; fi
    [[ -d $directory && $(stat -c '%u' "$directory") == 0 ]] || die "$directory must be a root-owned directory"
    mode=$(stat -c '%a' "$directory")
    (( (8#$mode & 0022) == 0 )) || die "$directory must not be group/world writable"
    if [[ $directory == /var/lib/sovagrid-vpn ]]; then
      (( (8#$mode & 0077) == 0 )) || die 'SovaGrid VPN state must be private (0700)'
    fi
  done
  [[ ! -L /usr/local/libexec ]] || die '/usr/local/libexec must not be a symlink'
  if [[ ! -e /usr/local/libexec ]]; then install -d -o root -g root -m 0755 /usr/local/libexec; fi
  for directory in /usr/local /usr/local/bin /usr/local/libexec; do
    [[ ! -L $directory && $(stat -c '%u:%a' "$directory") == 0:755 ]] || die "$directory must be root-owned mode 0755"
  done
  for item in 'sovagrid-vpn-ctl:/usr/local/bin/sovagrid-vpn-ctl' 'sovagrid-vpn-broker:/usr/local/libexec/sovagrid-vpn-broker'; do
    source_file=${item%%:*}
    destination=${item#*:}
    if [[ -e $destination || -L $destination ]]; then
      [[ ! -L $destination && -f $destination && $(sed -n '2p' "$destination") == '# Managed by SovaGrid run.sh' ]] || die "$destination is not a SovaGrid-managed regular file"
    fi
    temporary=$(mktemp "$destination.XXXXXXXX")
    install -o root -g root -m 0755 "$source_root/sovagrid-vpn/deploy/$source_file" "$temporary"
    mv -Tf -- "$temporary" "$destination"
  done
  systemd-analyze verify "$source_root/sovagrid-vpn/deploy/sovagrid-vpn-control.service" \
    "$source_root/sovagrid-vpn/deploy/sovagrid-vpn-control.socket" || die 'VPN control systemd units are invalid'
  for unit in sovagrid-vpn-control.service sovagrid-vpn-control.socket; do
    destination=/etc/systemd/system/$unit
    [[ ! -L $destination ]] || die "$destination must not be a symlink"
    temporary=$(mktemp "$destination.XXXXXXXX")
    install -o root -g root -m 0644 "$source_root/sovagrid-vpn/deploy/$unit" "$temporary"
    mv -Tf -- "$temporary" "$destination"
  done
  touch /etc/sovagrid/.vpn-control-managed-by-run-sh
  chmod 0600 /etc/sovagrid/.vpn-control-managed-by-run-sh
  systemctl daemon-reload
  systemctl enable --now sovagrid-vpn-control.socket
  systemctl restart sovagrid-vpn-control.service
  systemctl is-active --quiet sovagrid-vpn-control.socket || die 'VPN control socket failed to start'
  systemctl is-active --quiet sovagrid-vpn-control.service || die 'VPN control broker failed to start'
  say 'managed WireGuard control socket is ready; no VPN interface was activated'
fi

if (( hub_only )); then
  for auto_unit in sovagrid-hub-only-update.service sovagrid-hub-only-update.timer; do
    auto_source="$source_root/sovagrid-blueprint/deploy/$auto_unit"
    [[ -f $auto_source && ! -L $auto_source ]] || die "Hub-only update unit $auto_unit is missing or a symlink"
    auto_destination="/etc/systemd/system/$auto_unit"
    [[ ! -L $auto_destination ]] || die "Hub-only update unit $auto_destination must not be a symlink"
    auto_temporary=$(mktemp "$auto_destination.XXXXXXXX")
    if ! install -o root -g root -m 0644 "$auto_source" "$auto_temporary" ||
       ! mv -Tf -- "$auto_temporary" "$auto_destination"; then
      rm -f -- "$auto_temporary"
      die "Hub-only update unit $auto_unit could not be installed"
    fi
  done
  recovery_unit=sovagrid-external-agent-recovery.service
  recovery_source="$source_root/sovagrid-blueprint/deploy/$recovery_unit"
  recovery_destination="/etc/systemd/system/$recovery_unit"
  recovery_marker=/etc/sovagrid/.external-agent-recovery-managed-by-run-sh
  [[ -f $recovery_source && ! -L $recovery_source ]] || die 'external Agent recovery unit is missing or a symlink'
  systemd-analyze verify "$recovery_source" || die 'external Agent recovery unit is invalid'
  if [[ -e $recovery_destination || -L $recovery_destination ]]; then
    [[ -f $recovery_destination && ! -L $recovery_destination &&
       -f $recovery_marker && ! -L $recovery_marker &&
       $(stat -c '%u:%g:%a' "$recovery_marker") == 0:0:600 ]] ||
      die 'external Agent recovery unit is not managed by run.sh'
  fi
  if [[ -e $recovery_marker || -L $recovery_marker ]]; then
    [[ -f $recovery_marker && ! -L $recovery_marker &&
       $(stat -c '%u:%g:%a' "$recovery_marker") == 0:0:600 ]] ||
      die 'external Agent recovery marker is unsafe'
  fi
  recovery_temporary=$(mktemp "$recovery_destination.XXXXXXXX")
  if ! install -o root -g root -m 0644 "$recovery_source" "$recovery_temporary" ||
     ! mv -Tf -- "$recovery_temporary" "$recovery_destination"; then
    rm -f -- "$recovery_temporary"
    die 'external Agent recovery unit could not be installed'
  fi
  install -o root -g root -m 0600 /dev/null "$recovery_marker"
  systemctl daemon-reload
  if [[ -f /etc/systemd/system/sovagrid-agent.service &&
        ! -L /etc/systemd/system/sovagrid-agent.service ]]; then
    systemctl enable "$recovery_unit" || die 'external Agent recovery unit could not be enabled'
    systemctl is-enabled --quiet "$recovery_unit" || die 'external Agent recovery unit is not enabled'
  fi
  install_release_feed_units
  say 'Agent was skipped by --hub-only. Re-run without it to enroll the host.'
  exit 0
fi

agent_config=/etc/sovagrid/agent.json
agent_token=/etc/sovagrid/agent.token
if [[ -e $agent_config || -e $agent_token ]]; then
  [[ -f $agent_config && -f $agent_token && ! -L $agent_config && ! -L $agent_token ]] || die 'Agent config/token is incomplete or a symlink; inspect it manually'
else
  [[ -f $admin_password && ! -L $admin_password ]] || die 'existing Hub database needs the current admin password in /etc/sovagrid/admin-password for Agent enrollment'
  [[ $(stat -c '%u:%a' "$admin_password") == 0:600 ]] || die 'admin password must be root-owned, mode 0600'
  python3 "$blueprint_dir/deploy/enroll_agent.py" \
    --name "$(hostname -s)" \
    --config "$agent_config" \
    --token "$agent_token" \
    --ca /etc/sovagrid/hub-ca.pem \
    --password-file "$admin_password" \
    --gid "$(getent group sovagrid | cut -d: -f3)"
fi

[[ ! -L $agent_config && ! -L $agent_token ]] || die 'Agent config and token must not be symlinks'
chown root:sovagrid "$agent_config" "$agent_token"
chmod 0640 "$agent_config" "$agent_token"
if (( with_terminal )); then
  runuser -u sovagrid-shell -- test ! -r "$agent_token" || die 'PTY shell can read Agent token'
fi

for file in "$source_root"/sovagrid-agent/sovagrid_agent/*.py; do
  install -o root -g root -m 0644 "$file" "/opt/sovagrid-agent/sovagrid_agent/$(basename "$file")"
done
if (( with_containers )); then
  systemd-analyze verify "$source_root/sovagrid-agent/deploy/sovagrid-container-inventory.service" \
    "$source_root/sovagrid-agent/deploy/sovagrid-container-inventory.timer" || die 'container inventory systemd units are invalid'
  for container_unit in sovagrid-container-inventory.service sovagrid-container-inventory.timer; do
    destination=/etc/systemd/system/$container_unit
    [[ ! -L $destination ]] || die "$destination must not be a symlink"
    temporary=$(mktemp "$destination.XXXXXXXX")
    install -o root -g root -m 0644 "$source_root/sovagrid-agent/deploy/$container_unit" "$temporary"
    mv -Tf -- "$temporary" "$destination"
  done
fi
if (( with_terminal )); then
  systemd-analyze verify "$source_root/sovagrid-agent/deploy/sovagrid-terminal-control.service" \
    "$source_root/sovagrid-agent/deploy/sovagrid-terminal-control.socket" || die 'terminal broker systemd units are invalid'
  for unit in sovagrid-terminal-control.service sovagrid-terminal-control.socket; do
    destination=/etc/systemd/system/$unit
    [[ ! -L $destination ]] || die "$destination must not be a symlink"
    temporary=$(mktemp "$destination.XXXXXXXX")
    install -o root -g root -m 0644 "$source_root/sovagrid-agent/deploy/$unit" "$temporary"
    mv -Tf -- "$temporary" "$destination"
  done
  touch /etc/sovagrid/.terminal-unit-managed-by-run-sh
  chmod 0600 /etc/sovagrid/.terminal-unit-managed-by-run-sh
fi
if (( with_journal )); then
  systemd-analyze verify "$source_root/sovagrid-agent/deploy/sovagrid-journal-control.service" \
    "$source_root/sovagrid-agent/deploy/sovagrid-journal-control.socket" || die 'journal broker systemd units are invalid'
  for journal_unit_file in sovagrid-journal-control.service sovagrid-journal-control.socket; do
    destination=/etc/systemd/system/$journal_unit_file
    [[ ! -L $destination ]] || die "$destination must not be a symlink"
    temporary=$(mktemp "$destination.XXXXXXXX")
    install -o root -g root -m 0644 "$source_root/sovagrid-agent/deploy/$journal_unit_file" "$temporary"
    mv -Tf -- "$temporary" "$destination"
  done
  journal_policy=/etc/sovagrid-journal/units.json
  if (( journal_requested )); then
    python3 - "$journal_policy" "$(getent group sovagrid-journal | cut -d: -f3)" "${journal_units[@]}" <<'PY'
import json, os, pathlib, re, stat, sys, tempfile
path = pathlib.Path(sys.argv[1])
gid = int(sys.argv[2])
units = sys.argv[3:]
pattern = re.compile(r"[A-Za-z0-9_.@-]{1,96}\.service\Z")
if not 1 <= len(units) <= 16 or len(set(units)) != len(units) or any(not pattern.fullmatch(unit) for unit in units):
    raise SystemExit("invalid journal unit list")
if path.exists() or path.is_symlink():
    current = path.lstat()
    if not stat.S_ISREG(current.st_mode) or current.st_uid != 0 or current.st_gid != gid or stat.S_IMODE(current.st_mode) != 0o640:
        raise SystemExit("journal policy has unsafe owner, mode or type")
fd, temporary = tempfile.mkstemp(prefix=".units-", dir=str(path.parent))
try:
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump({"units": units}, stream, separators=(",", ":"))
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.chown(temporary, 0, gid)
    os.chmod(temporary, 0o640)
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PY
  else
    [[ -f $journal_policy && ! -L $journal_policy &&
       $(stat -c '%U:%G:%a' "$journal_policy") == root:sovagrid-journal:640 ]] || die 'managed journal policy is missing or unsafe'
  fi
fi
unit=/etc/systemd/system/sovagrid-agent.service
marker=/etc/sovagrid/.agent-unit-managed-by-run-sh
install -o root -g root -m 0644 "$source_root/sovagrid-agent/deploy/sovagrid-agent.service" "$unit"
touch "$marker"
chmod 0600 "$marker"
systemctl daemon-reload
if (( with_containers )); then
  systemctl enable --now sovagrid-container-inventory.timer
  systemctl start sovagrid-container-inventory.service
  systemctl is-active --quiet sovagrid-container-inventory.timer || die 'container inventory timer failed to start'
  [[ -f /var/lib/sovagrid-containers/snapshot.json && ! -L /var/lib/sovagrid-containers/snapshot.json &&
     $(stat -c '%U:%G:%a:%h' /var/lib/sovagrid-containers/snapshot.json) == root:sovagrid:640:1 ]] || die 'container inventory snapshot is unsafe'
  runuser -u sovagrid -- /usr/bin/python3 -I - <<'PY' || die 'Agent cannot read the sanitized container snapshot'
import sys
sys.path.insert(0, '/opt/sovagrid-agent')
from sovagrid_agent.containers import read_snapshot
if read_snapshot() is None:
    raise SystemExit('container snapshot unreadable')
PY
  touch /etc/sovagrid/.containers-managed-by-run-sh
  chown root:root /etc/sovagrid/.containers-managed-by-run-sh
  chmod 0600 /etc/sovagrid/.containers-managed-by-run-sh
fi
if (( with_terminal )); then
  systemctl enable --now sovagrid-terminal-control.socket
  systemctl restart sovagrid-terminal-control.service
  systemctl is-active --quiet sovagrid-terminal-control.socket || die 'terminal broker socket failed to start'
  systemctl is-active --quiet sovagrid-terminal-control.service || die 'terminal broker failed to start'
fi
if (( with_journal )); then
  systemctl enable --now sovagrid-journal-control.socket
  systemctl try-restart sovagrid-journal-control.service
  systemctl is-active --quiet sovagrid-journal-control.socket || die 'journal broker socket failed to start'
  journal_probe_unit=$(python3 - "$journal_policy" <<'PY'
import json, pathlib, sys
units = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))['units']
if not units:
    raise SystemExit('journal policy has no units')
print(units[0])
PY
)
  runuser -u sovagrid -- /usr/bin/python3 -I - "$journal_probe_unit" <<'PY' || die 'journal broker failed its local read-only probe'
import json, socket, sys
request = json.dumps({'unit': sys.argv[1], 'lines': 1}, separators=(',', ':')).encode() + b'\n'
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.settimeout(10)
    client.connect('/run/sovagrid-journal/control.sock')
    client.sendall(request)
    response = bytearray()
    while b'\n' not in response and len(response) <= 16384:
        chunk = client.recv(16385 - len(response))
        if not chunk:
            raise SystemExit('journal broker closed without a response')
        response.extend(chunk)
    result = json.loads(response)
    if result.get('state') not in ('succeeded', 'output_limited'):
        raise SystemExit('journal broker did not return an allowed read')
PY
  systemctl is-active --quiet sovagrid-journal-control.service || die 'journal broker failed to start'
  for broad_group in systemd-journal adm; do
    if id -nG sovagrid | tr ' ' '\n' | grep -Fxq "$broad_group"; then
      die "Agent user must not have broad $broad_group access"
    fi
  done
  touch /etc/sovagrid/.journal-managed-by-run-sh
  chown root:root /etc/sovagrid/.journal-managed-by-run-sh
  chmod 0600 /etc/sovagrid/.journal-managed-by-run-sh
fi
if (( terminal_requested || files_requested || journal_requested || journal_disable_requested )); then
  # Enable Agent polling only after the optional local facilities are ready.
  python3 - "$agent_config" "$terminal_requested" "$files_requested" "$journal_requested" "$journal_disable_requested" "${journal_units[@]}" <<'PY'
import json, os, pathlib, re, sys, tempfile
path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
if not isinstance(value, dict):
    raise SystemExit("invalid Agent configuration")
if int(sys.argv[2]):
    value["allow_remote_commands"] = True
    value["allow_interactive_terminal"] = True
if int(sys.argv[3]):
    roots = value.get("file_roots", {})
    if not isinstance(roots, dict) or roots.get("workspace", "/var/lib/sovagrid-agent/files") != "/var/lib/sovagrid-agent/files":
        raise SystemExit("file_roots.workspace conflicts with the managed file root")
    roots["workspace"] = "/var/lib/sovagrid-agent/files"
    value["file_roots"] = roots
    value["allow_remote_commands"] = True
    value["allow_file_manager"] = True
if int(sys.argv[4]):
    units = sys.argv[6:]
    pattern = re.compile(r"[A-Za-z0-9_.@-]{1,96}\.service\Z")
    if not 1 <= len(units) <= 16 or len(set(units)) != len(units) or any(not pattern.fullmatch(unit) for unit in units):
        raise SystemExit("invalid journal unit list")
    value["allow_remote_commands"] = True
    value["allow_systemd_journal"] = True
    value["journal_units"] = units
if int(sys.argv[5]):
    value["allow_systemd_journal"] = False
    value["journal_units"] = []
fd, temporary = tempfile.mkstemp(prefix=".agent-features-", dir=str(path.parent))
try:
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, separators=(",", ":"))
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.chown(temporary, 0, path.stat().st_gid)
    os.chmod(temporary, 0o640)
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PY
fi
if (( journal_disable_requested )); then
  systemctl disable --now sovagrid-journal-control.socket || {
    if systemctl is-active --quiet sovagrid-journal-control.socket; then die 'journal broker socket could not be disabled'; fi
  }
  systemctl stop sovagrid-journal-control.service || {
    if systemctl is-active --quiet sovagrid-journal-control.service; then die 'journal broker service could not be stopped'; fi
  }
  if systemctl is-active --quiet sovagrid-journal-control.socket; then die 'journal broker socket remained active'; fi
  if systemctl is-active --quiet sovagrid-journal-control.service; then die 'journal broker service remained active'; fi
  if [[ -d /etc/sovagrid-journal ]]; then
    rm -f -- /etc/sovagrid-journal/units.json
    rmdir -- /etc/sovagrid-journal
  fi
  rm -f -- /etc/systemd/system/sovagrid-journal-control.service /etc/systemd/system/sovagrid-journal-control.socket
  rm -f -- /etc/sovagrid/.journal-managed-by-run-sh
  systemctl daemon-reload
  say 'journal viewer disabled; its policy and socket were removed'
fi
if (( containers_disable_requested )); then
  systemctl disable --now sovagrid-container-inventory.timer || {
    if systemctl is-active --quiet sovagrid-container-inventory.timer; then die 'container inventory timer could not be disabled'; fi
  }
  systemctl stop sovagrid-container-inventory.service || {
    if systemctl is-active --quiet sovagrid-container-inventory.service; then die 'container inventory service could not be stopped'; fi
  }
  rm -f -- /var/lib/sovagrid-containers/snapshot.json
  rmdir -- /var/lib/sovagrid-containers
  rm -f -- /etc/systemd/system/sovagrid-container-inventory.service /etc/systemd/system/sovagrid-container-inventory.timer
  rm -f -- /etc/sovagrid/.containers-managed-by-run-sh
  systemctl daemon-reload
  say 'container inventory disabled; its timer and snapshot were removed'
fi
systemctl enable sovagrid-agent.service
systemctl restart sovagrid-agent.service
systemctl is-active --quiet sovagrid-agent.service || die 'Agent failed to start; inspect journalctl -u sovagrid-agent'
for auto_unit in sovagrid-auto-update.service sovagrid-auto-update.timer; do
  auto_source="$source_root/sovagrid-blueprint/deploy/$auto_unit"
  [[ -f $auto_source && ! -L $auto_source ]] || die "auto-update unit $auto_unit is missing or a symlink"
  install -o root -g root -m 0644 "$auto_source" "/etc/systemd/system/$auto_unit"
done
systemctl daemon-reload
systemctl enable --now sovagrid-auto-update.timer
systemctl is-active --quiet sovagrid-auto-update.timer || die 'auto-update timer failed to start'
install_release_feed_units
say 'host Agent is active under the unprivileged sovagrid user'
say 'open the web panel through: ssh -L 8766:127.0.0.1:8766 root@HOST ; then http://127.0.0.1:8766'
