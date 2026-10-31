#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
# One-command, first-server bootstrap. Download exactly one reviewed release;
# the bundled run.sh remains the installer for Docker, systemd and services.
set -Eeuo pipefail
umask 077

release='server-v0.13.0'
archive_sha256='7f42a3e3bf47ae63bd42cb4dac841880d9958376b610b59be343f83f1f780d17'
manifest_sha256='f6d3b246d29661ffac4975f78dbc3a5481405b47e23826ea30a388e41f2b1280'
archive_url="https://github.com/sovagrid/sovagrid-blueprint/releases/download/${release}/SovaGrid-server-source.tar.gz"
source_root='/opt/sovagrid-src'
default_path='/sovagrid/monitoring/'
default_root_behavior='untouched'

say() { printf 'SovaGrid: %s\n' "$*"; }
die() { printf 'SovaGrid: %s\n' "$*" >&2; exit 1; }

[[ ${EUID} -eq 0 ]] || die 'запустите команду через sudo (права root нужны для установки)'
[[ -r /etc/os-release ]] || die 'не удалось определить ОС'
# shellcheck disable=SC1091
. /etc/os-release
[[ ${ID:-} == ubuntu ]] || die 'первичная установка поддерживает Ubuntu'
[[ ${VERSION_ID:-} == 22.04 || ${VERSION_ID:-} == 24.04 || ${VERSION_ID:-} == 26.04 ]] ||
  die 'нужна Ubuntu 22.04, 24.04 или 26.04'
command -v curl >/dev/null || die 'нужен curl для загрузки установщика'
command -v sha256sum >/dev/null || die 'нужна утилита sha256sum'
command -v tar >/dev/null || die 'нужна утилита tar'
command -v flock >/dev/null || die 'нужна утилита flock'
[[ -d /run/systemd/system ]] || die 'нужен сервер Ubuntu с systemd'
[[ -d /opt && ! -L /opt && $(stat -c %u /opt) == 0 &&
   -z $(find /opt -maxdepth 0 -perm /022 -print -quit) ]] ||
  die 'каталог /opt должен принадлежать root и быть недоступным для записи другим'
[[ ! -e $source_root && ! -L $source_root ]] ||
  die 'SovaGrid уже установлен или исходники заняты; откройте панель или Connect для обновления'
[[ ! -e /var/lib/sovagrid/.managed-by-run-sh && ! -L /var/lib/sovagrid/.managed-by-run-sh ]] ||
  die 'SovaGrid уже установлен; обновление выполняется через панель или Connect'

# curl | sudo bash leaves stdin connected to the script. Read optional public
# settings from the terminal, never from its script stream or an argv secret.
panel_path=${SOVAGRID_PANEL_PATH:-$default_path}
public_address=${SOVAGRID_PUBLIC_ADDRESS:-}
root_behavior=${SOVAGRID_ROOT_BEHAVIOR:-$default_root_behavior}
tty_fd=''
if [[ -z ${SOVAGRID_SETUP_NONINTERACTIVE:-} ]] &&
   { exec {tty_fd}<>/dev/tty; } 2>/dev/null; then
  say 'Первичная настройка. Enter сохраняет значение в квадратных скобках.'
  printf 'Путь панели [%s]: ' "$panel_path" >&"$tty_fd"
  IFS= read -r answer <&"$tty_fd" || answer=''
  [[ -z $answer ]] || panel_path=$answer
  printf 'Публичный домен или статический IPv4 (Enter — только доступ через SSH) [%s]: ' "$public_address" >&"$tty_fd"
  IFS= read -r answer <&"$tty_fd" || answer=''
  [[ -z $answer ]] || public_address=$answer
fi
[[ $panel_path =~ ^/([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?/){1,3}$ &&
   ${#panel_path} -le 96 && $panel_path != /api/* && $panel_path != /healthz/* ]] ||
  die 'путь панели должен иметь вид /sovagrid/monitoring/ (до трёх сегментов)'
[[ $root_behavior == untouched || $root_behavior == panel ||
   $root_behavior == redirect || $root_behavior == not_found ]] ||
  die 'неверное поведение корня сайта'
[[ -z $public_address || ( ${#public_address} -le 253 && $public_address != *[[:space:]]* ) ]] ||
  die 'неверный публичный адрес'

[[ ! -L /run/sovagrid-bootstrap.lock ]] || die 'небезопасный файл блокировки установки'
if [[ ! -e /run/sovagrid-bootstrap.lock ]]; then
  install -o root -g root -m 0600 /dev/null /run/sovagrid-bootstrap.lock
fi
[[ -f /run/sovagrid-bootstrap.lock &&
   $(stat -c '%u:%g:%a:%h' /run/sovagrid-bootstrap.lock) == 0:0:600:1 ]] ||
  die 'небезопасные права файла блокировки установки'
exec 9>>/run/sovagrid-bootstrap.lock
flock -n 9 || die 'другая первичная установка уже выполняется'
[[ ! -e $source_root && ! -L $source_root ]] || die 'исходники появились во время подготовки'
stage=$(mktemp -d /opt/.sovagrid-bootstrap.XXXXXXXX) || die 'не удалось создать закрытый временный каталог'
chmod 0700 "$stage"
cleanup() { rm -rf -- "$stage"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

say "Скачиваю проверенный выпуск ${release}…"
curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' \
  --connect-timeout 15 --max-time 240 --max-filesize 67108864 \
  --output "$stage/source.tar.gz" "$archive_url" || die 'не удалось скачать выпуск по HTTPS'
[[ -s $stage/source.tar.gz && $(stat -c %s "$stage/source.tar.gz") -le 67108864 ]] ||
  die 'архив пуст или превышает допустимый размер'
printf '%s  %s\n' "$archive_sha256" "$stage/source.tar.gz" | sha256sum --check --status ||
  die 'SHA-256 архива не совпадает с проверенным выпуском'
actual_manifest=$(tar -xOzf "$stage/source.tar.gz" sovagrid-bundle.json | sha256sum | cut -d' ' -f1) ||
  die 'манифест пакета повреждён'
[[ $actual_manifest == "$manifest_sha256" ]] || die 'SHA-256 манифеста не совпадает'

install -d -o root -g root -m 0755 "$stage/source"
tar --no-same-owner --same-permissions -xzf "$stage/source.tar.gz" -C "$stage/source" ||
  die 'не удалось распаковать проверенный пакет'
[[ -f $stage/source/sovagrid-blueprint/run.sh && ! -L $stage/source/sovagrid-blueprint/run.sh ]] ||
  die 'в проверенном пакете нет установщика'
[[ ! -e $source_root && ! -L $source_root ]] || die 'исходники появились во время загрузки'
mv -Tn -- "$stage/source" "$source_root"
[[ ! -e $stage/source && ! -L $stage/source && -f $source_root/sovagrid-bundle.json ]] ||
  die 'не удалось безопасно разместить исходники'
[[ $(sha256sum "$source_root/sovagrid-bundle.json" | cut -d' ' -f1) == "$manifest_sha256" ]] ||
  die 'исходники изменились после распаковки'

say 'Ставлю Hub, Web, Agent и зависимости; включаю терминал, файлы и WireGuard…'
options=(--with-terminal --with-files --with-wireguard --with-containers)
if systemctl list-unit-files ssh.service --no-legend 2>/dev/null | grep -q '^ssh\.service '; then
  options+=(--with-journal --journal-unit ssh.service)
fi
bash "$source_root/sovagrid-blueprint/run.sh" "${options[@]}" ||
  die 'установка прервалась; исходники сохранены для диагностики, состояние служб не очищено'

say 'Вход в Hub: admin. После входа смените начальный пароль в настройках.'
if [[ -n $tty_fd && -r /etc/sovagrid/admin-password ]]; then
  printf 'SovaGrid: начальный пароль (только в этом терминале): ' >&"$tty_fd"
  cat /etc/sovagrid/admin-password >&"$tty_fd"
else
  say 'Начальный пароль хранится в /etc/sovagrid/admin-password (доступен только root).'
fi

# The installed, hash-pinned helpers own all Caddy/Compose changes and perform
# preview/CAS/health/rollback. The wrapper never writes their state directly.
if ! python3 -B -I - "$public_address" "$panel_path" "$root_behavior" <<'PY'
import ipaddress
import json
import subprocess
import sys

address, panel_path, root_behavior = sys.argv[1:]
public = bool(address)
try:
    mode = 'ip' if public and ipaddress.ip_address(address) else 'dns'
except ValueError:
    mode = 'dns'
config = ({'mode': mode, 'address': address, 'acme_environment': 'production',
           'panel_path': panel_path, 'root_behavior': root_behavior} if public else
          {'panel_path': panel_path, 'root_behavior': root_behavior})
script = ('/opt/sovagrid-src/sovagrid-blueprint/deploy/' +
          ('public_web.py' if public else 'local_web.py'))

def call(action, value):
    raw = None if value is None else (json.dumps(value, separators=(',', ':')) + '\n').encode()
    reply = subprocess.run([sys.executable, '-B', '-I', script, action], input=raw,
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=480, check=False)
    if len(reply.stdout) > 8192:
        raise ValueError('large reply')
    result = json.loads(reply.stdout)
    if reply.returncode or result.get('ok') is not True:
        error = result.get('error', {})
        raise ValueError(error.get('message', 'настройка не завершилась'))
    return result

try:
    preview = call('preview', {'config': config})
    result = call('apply', {'config': config,
                            'expected_state_sha256': preview['expected_state_sha256'],
                            'source_manifest_sha256': preview['source_manifest_sha256']})
except (ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
    print('SovaGrid: настройка адреса не завершилась: ' + str(error), file=sys.stderr)
    raise SystemExit(1)
print('SovaGrid: панель: ' +
      (result['url'] + panel_path if public else 'http://127.0.0.1:8766' + panel_path))
PY
then
  die 'Hub установлен, но путь/HTTPS не настроен. Добавьте этот сервер по SSH в Connect или мобильном приложении и откройте панель; либо выполните с компьютера ssh -L 8766:127.0.0.1:8766 USER@SERVER и откройте http://127.0.0.1:8766/sovagrid/monitoring/. Публичный адрес можно настроить в разделе Web.'
fi

say 'Установка завершена. Дополнительные серверы подключаются из панели или приложения по SSH.'
