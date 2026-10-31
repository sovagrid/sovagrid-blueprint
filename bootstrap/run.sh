#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
# One-command, first-server bootstrap. Download exactly one reviewed release;
# the bundled run.sh remains the installer for Docker, systemd and services.
set -Eeuo pipefail
umask 077

release='server-v0.14.1'
archive_sha256='c5786bb64467063196046144e665a98e347f40713facb37809b65a03eb70f347'
manifest_sha256='ec6f567b0292916dd3f104f1441451708a955b79d02ef91f82237a8cf8603f1f'
archive_url="https://github.com/sovagrid/sovagrid-blueprint/releases/download/${release}/SovaGrid-server-source.tar.gz"
source_root='/opt/sovagrid-src'
default_path='/sovagrid/monitoring/'
default_root_behavior='untouched'

say() { printf 'SovaGrid: %s\n' "$*"; }
die() { printf 'SovaGrid: %s\n' "$*" >&2; exit 1; }

setup_mode=install
panel_path=${SOVAGRID_PANEL_PATH:-}
public_address=${SOVAGRID_PUBLIC_ADDRESS:-}
public_address_supplied=0
if [[ ${SOVAGRID_PUBLIC_ADDRESS+x} ]]; then public_address_supplied=1; fi
root_behavior=${SOVAGRID_ROOT_BEHAVIOR:-}
while (( $# )); do
  case $1 in
    --configure-web) setup_mode=configure; shift ;;
    --public-address|--panel-path|--root-behavior)
      (( $# >= 2 )) || die "для $1 нужно значение"
      case $1 in
        --public-address) public_address=$2; public_address_supplied=1 ;;
        --panel-path) panel_path=$2 ;;
        --root-behavior) root_behavior=$2 ;;
      esac
      shift 2 ;;
    *) die "неизвестный параметр: $1" ;;
  esac
done

suggest_public_ipv4() {
  command -v python3 >/dev/null 2>&1 && command -v ip >/dev/null 2>&1 || return 0
  python3 -B -I - <<'PY'
# SOVAGRID_BOOTSTRAP_ADDRESS_SUGGESTION_PY
import ipaddress
import json
import subprocess

def single_public_ipv4(interfaces):
    addresses = set()
    if not isinstance(interfaces, list):
        return ''
    for interface in interfaces:
        if (not isinstance(interface, dict) or
                not isinstance(interface.get('flags'), list) or
                'UP' not in interface['flags'] or
                not isinstance(interface.get('addr_info'), list)):
            continue
        for record in interface['addr_info']:
            if (not isinstance(record, dict) or record.get('family') != 'inet' or
                    record.get('scope') != 'global' or
                    not isinstance(record.get('local'), str)):
                continue
            try:
                address = ipaddress.IPv4Address(record['local'])
            except ipaddress.AddressValueError:
                continue
            if address.is_global and not address.is_multicast:
                addresses.add(str(address))
    return next(iter(addresses)) if len(addresses) == 1 else ''

def discover():
    try:
        reply = subprocess.run(['ip', '-j', '-4', 'address', 'show', 'scope', 'global'],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, timeout=5, check=False)
        if reply.returncode or len(reply.stdout) > 65536:
            return ''
        return single_public_ipv4(json.loads(reply.stdout))
    except (OSError, ValueError, subprocess.SubprocessError):
        return ''

if __name__ == '__main__':
    print(discover())
PY
}

suggest_address_if_interactive() {
  if [[ ${1:-0} == 1 && $setup_mode == install &&
        -z ${SOVAGRID_SETUP_NONINTERACTIVE:-} && $public_address_supplied == 0 ]]; then
    public_address=$(suggest_public_ipv4) || public_address=''
    if [[ -n $public_address ]]; then
      say "Найден публичный IPv4 сетевого интерфейса: $public_address. Enter выберет этот адрес."
    else
      say 'Публичный IPv4 не удалось определить однозначно. Укажите адрес вручную или выберите доступ только через SSH.'
    fi
  fi
}

apply_public_address_answer() {
  case ${1:-} in
    -) public_address='' ;;
    '') ;; # Enter accepts the suggested or explicitly supplied address.
    *) public_address=$1 ;;
  esac
}

bootstrap_installation_guard() {
  local installation_lock=/run/sovagrid-installation.lock
  [[ ! -L $installation_lock ]] || die 'небезопасная общая блокировка установки'
  if [[ ! -e $installation_lock ]]; then
    ( set -o noclobber; : > "$installation_lock" ) 2>/dev/null || die 'небезопасная общая блокировка установки'
  fi
  [[ -f $installation_lock && $(stat -c '%u:%g:%a:%h' "$installation_lock") == 0:0:600:1 ]] || die 'небезопасная общая блокировка установки'
  exec 6>>"$installation_lock"
  [[ $(stat -Lc '%d:%i' /proc/self/fd/6) == "$(stat -c '%d:%i' "$installation_lock")" ]] || die 'небезопасная общая блокировка установки'
  flock -n 6 || die 'другая установка, восстановление или обновление SovaGrid уже выполняется'
  [[ ! -e /var/lib/.sovagrid-host-restore-in-progress && ! -L /var/lib/.sovagrid-host-restore-in-progress ]] || die 'сначала завершите или отмените прерванное восстановление SovaGrid'
}

configure_web() {
python3 -B -I - "$source_root" "$manifest_sha256" "$public_address" "$panel_path" "$root_behavior" <<'PY'
# SOVAGRID_BOOTSTRAP_WEB_CONFIGURE_PY
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT_UID = 0
COMPONENTS = {'sovagrid-blueprint', 'sovagrid-hub', 'sovagrid-web', 'sovagrid-agent', 'sovagrid-vpn'}
SHA = re.compile(r'[0-9a-f]{64}\Z')

def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('повторяющееся поле манифеста')
        value[key] = item
    return value

def checked(path, directory=False, limit=8 * 1024 * 1024):
    info = path.lstat()
    if (info.st_uid != ROOT_UID or info.st_mode & 0o022 or
            (not stat.S_ISDIR(info.st_mode) if directory else
             not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit)):
        raise ValueError('небезопасный путь установленных исходников')
    if directory:
        return None
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    fingerprint = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid,
                                item.st_size, item.st_nlink, item.st_mtime_ns, item.st_ctime_ns)
    if len(raw) > limit or fingerprint(info) != fingerprint(before) or fingerprint(before) != fingerprint(after):
        raise ValueError('исходники изменились при проверке')
    return raw

def verify_source(root, expected):
    checked(root, directory=True)
    raw = checked(root / 'sovagrid-bundle.json', limit=512 * 1024)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('нужен проверенный server-v0.14.1; обновите старую установку через Connect')
    value = json.loads(raw, object_pairs_hook=unique)
    if (not isinstance(value, dict) or set(value) != {'format', 'components', 'sha256'} or
            type(value['format']) is not int or value['format'] != 1 or
            not isinstance(value['components'], dict) or set(value['components']) != COMPONENTS or
            not isinstance(value['sha256'], dict) or
            set(item.name for item in root.iterdir()) != COMPONENTS | {'sovagrid-bundle.json'}):
        raise ValueError('неверный манифест установленных исходников')
    for name, digest in value['sha256'].items():
        if (not isinstance(name, str) or len(name) > 240 or
                re.fullmatch(r'[A-Za-z0-9_.@-]+(?:/[A-Za-z0-9_.@-]+)*', name) is None or
                any(part in ('.', '..') for part in name.split('/')) or
                name.split('/')[0] not in COMPONENTS or not isinstance(digest, str) or not SHA.fullmatch(digest)):
            raise ValueError('неверный путь манифеста исходников')
    actual = set()
    for parent, directories, files in os.walk(root, followlinks=False):
        for name in directories:
            checked(Path(parent) / name, directory=True)
        for name in files:
            path = Path(parent) / name
            relative = path.relative_to(root).as_posix()
            if relative == 'sovagrid-bundle.json':
                continue
            payload = checked(path)
            if hashlib.sha256(payload).hexdigest() != value['sha256'].get(relative):
                raise ValueError('установленные исходники изменены')
            actual.add(relative)
    if actual != set(value['sha256']):
        raise ValueError('набор установленных исходников изменён')

class HelperError(ValueError):
    pass

def helper_call(root, helper, action, value=None):
    raw = None if value is None else (json.dumps(value, separators=(',', ':')) + '\n').encode()
    reply = subprocess.run([sys.executable, '-B', '-I', str(root / 'sovagrid-blueprint/deploy' / helper), action],
                           input=raw, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=480, check=False)
    if len(reply.stdout) > 8192:
        raise HelperError('слишком большой ответ настройки Web')
    result = json.loads(reply.stdout, object_pairs_hook=unique)
    if reply.returncode or not isinstance(result, dict) or result.get('ok') is not True:
        error = result.get('error', {}) if isinstance(result, dict) else {}
        raise HelperError(error.get('message', 'настройка Web не завершилась'))
    return result

def configure(address, requested_path, requested_root, call, validate):
    public_status = call('public_web.py', 'status')
    local_status = call('local_web.py', 'status')
    previous = public_status.get('config') or local_status.get('config') or {}
    panel_path = requested_path or previous.get('panel_path', '/sovagrid/monitoring/')
    root_behavior = requested_root or previous.get('root_behavior', 'untouched')
    try:
        mode = 'ip' if ipaddress.ip_address(address) else 'dns'
    except ValueError:
        mode = 'dns'
    public = bool(address)
    config = ({'mode': mode, 'address': address, 'acme_environment': 'production',
               'panel_path': panel_path, 'root_behavior': root_behavior} if public else
              {'panel_path': panel_path, 'root_behavior': root_behavior})
    if public:
        config = validate(config)  # Reject invalid input before disabling local access.
    helper = 'public_web.py' if public else 'local_web.py'
    released = None
    try:
        if public and local_status.get('enabled'):
            if public_status.get('enabled'):
                raise HelperError('локальный и публичный режимы одновременно активны')
            released = call('local_web.py', 'disable',
                            {'expected_state_sha256': local_status['expected_state_sha256']})
        preview = call(helper, 'preview', {'config': config})
        result = call(helper, 'apply', {'config': config,
                      'expected_state_sha256': preview['expected_state_sha256'],
                      'source_manifest_sha256': preview['source_manifest_sha256']})
    except Exception as error:
        if released is not None:
            try:
                now_public = call('public_web.py', 'status')
                now_local = call('local_web.py', 'status')
                expected = released['expected_state_sha256']
                if (now_public.get('enabled') or now_local.get('enabled') or
                        now_local['expected_state_sha256'] != expected):
                    raise HelperError('настройки изменены другой операцией')
                restore = call('local_web.py', 'preview', {'config': local_status['config']})
                if restore['expected_state_sha256'] != expected:
                    raise HelperError('настройки изменены другой операцией')
                call('local_web.py', 'apply', {'config': local_status['config'],
                     'expected_state_sha256': expected,
                     'source_manifest_sha256': restore['source_manifest_sha256']})
            except Exception as rollback_error:
                raise HelperError(str(error) + '; восстановление локального пути не подтверждено: ' +
                                  str(rollback_error)) from error
            raise HelperError(str(error) + '; прежний локальный путь восстановлен') from error
        raise
    return (result['url'] if public else 'http://127.0.0.1:8766') + panel_path

def main(argv):
    root, expected, address, panel_path, root_behavior = argv
    root = Path(root)
    verify_source(root, expected)
    # The file is imported only after every source byte matches the pinned manifest.
    module_path = root / 'sovagrid-blueprint/deploy/public_web.py'
    spec = importlib.util.spec_from_file_location('sovagrid_verified_public_web', module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    call = lambda helper, action, value=None: helper_call(root, helper, action, value)
    return configure(address, panel_path, root_behavior, call, module.validate_config)

if __name__ == '__main__':
    try:
        print('SovaGrid: панель: ' + main(sys.argv[1:]))
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        print('SovaGrid: настройка адреса не завершилась: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
PY
}

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
if [[ $setup_mode == configure ]]; then
  [[ -n $public_address ]] || die 'укажите --public-address ДОМЕН_ИЛИ_IP'
  command -v python3 >/dev/null || die 'в установленной системе нет python3'
  [[ -f /var/lib/sovagrid/.managed-by-run-sh && ! -L /var/lib/sovagrid/.managed-by-run-sh &&
     $(stat -c '%u:%g:%a:%h' /var/lib/sovagrid/.managed-by-run-sh) == 0:0:600:1 ]] ||
    die 'нужна установленная управляемая SovaGrid'
  bootstrap_installation_guard
  configure_web || die 'публичный доступ не настроен; проверьте адрес и доступность TCP 80/443'
  say 'Публичный HTTPS настроен. Используйте прежние логин и пароль Hub.'
  exit 0
fi
[[ ! -e $source_root && ! -L $source_root ]] ||
  die 'SovaGrid уже установлен; для адреса используйте --configure-web --public-address ДОМЕН_ИЛИ_IP'
[[ ! -e /var/lib/sovagrid/.managed-by-run-sh && ! -L /var/lib/sovagrid/.managed-by-run-sh ]] ||
  die 'SovaGrid уже установлен; обновление выполняется через панель или Connect'

# curl | sudo bash leaves stdin connected to the script. Read optional public
# settings from the terminal, never from its script stream or an argv secret.
panel_path=${panel_path:-$default_path}
root_behavior=${root_behavior:-$default_root_behavior}
tty_fd=''
if [[ -z ${SOVAGRID_SETUP_NONINTERACTIVE:-} ]] &&
   { exec {tty_fd}<>/dev/tty; } 2>/dev/null; then
  say 'Первичная настройка. Enter сохраняет значение в квадратных скобках.'
  printf 'Путь панели [%s]: ' "$panel_path" >&"$tty_fd"
  IFS= read -r answer <&"$tty_fd" || answer=''
  [[ -z $answer ]] || panel_path=$answer
  say 'Адрес веб-панели — ссылка для открытия этой панели с телефона и в браузере через интернет без SSH-туннеля.'
  say 'Введите публичный IPv4 этого Ubuntu-сервера из панели провайдера или домен, указывающий на него.'
  say 'Домен не обязателен. Если используете домен, вы должны управлять его DNS и направить его на этот сервер.'
  say 'Это адрес самой панели; дополнительные серверы подключаются позже по SSH в интерфейсе.'
  say 'Для HTTPS сервер должен принимать входящие TCP-соединения на портах 80 и 443.'
  suggest_address_if_interactive 1
  say 'Введите -, чтобы оставить только SSH-туннель. Enter сохраняет адрес в скобках; без адреса выбирается только SSH.'
  printf 'Адрес веб-панели (IPv4 или свой домен) [%s]: ' "$public_address" >&"$tty_fd"
  IFS= read -r answer <&"$tty_fd" || answer=''
  apply_public_address_answer "$answer"
fi
[[ $panel_path =~ ^/([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?/){1,3}$ &&
   ${#panel_path} -le 96 && $panel_path != /api/* && $panel_path != /healthz/* ]] ||
  die 'путь панели должен иметь вид /sovagrid/monitoring/ (до трёх сегментов)'
[[ $root_behavior == untouched || $root_behavior == panel ||
   $root_behavior == redirect || $root_behavior == not_found ]] ||
  die 'неверное поведение корня сайта'
[[ -z $public_address || ( ${#public_address} -le 253 && $public_address != *[[:space:]]* ) ]] ||
  die 'неверный публичный адрес'
if [[ -z $public_address ]]; then
  say 'Выбран доступ только через SSH: публичная ссылка на панель после установки не появится.'
else
  say 'Выбран публичный HTTPS: после проверки сертификата установщик покажет ссылку для телефона и браузера.'
fi

[[ ! -L /run/sovagrid-bootstrap.lock ]] || die 'небезопасный файл блокировки установки'
if [[ ! -e /run/sovagrid-bootstrap.lock ]]; then
  install -o root -g root -m 0600 /dev/null /run/sovagrid-bootstrap.lock
fi
[[ -f /run/sovagrid-bootstrap.lock &&
   $(stat -c '%u:%g:%a:%h' /run/sovagrid-bootstrap.lock) == 0:0:600:1 ]] ||
  die 'небезопасные права файла блокировки установки'
exec 9>>/run/sovagrid-bootstrap.lock
flock -n 9 || die 'другая первичная установка уже выполняется'
bootstrap_installation_guard
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
SOVAGRID_INSTALLATION_LOCK_FD=6 bash "$source_root/sovagrid-blueprint/run.sh" "${options[@]}" ||
  die 'установка прервалась; исходники сохранены для диагностики, состояние служб не очищено'

say 'Вход в Hub: admin. После входа смените начальный пароль в настройках.'
if [[ -n $tty_fd && -r /etc/sovagrid/admin-password ]]; then
  printf 'SovaGrid: начальный пароль (только в этом терминале): ' >&"$tty_fd"
  cat /etc/sovagrid/admin-password >&"$tty_fd"
else
  say 'Начальный пароль хранится в /etc/sovagrid/admin-password (доступен только root).'
fi

# The verified installed helpers own Caddy/Compose state and rollback.
if ! configure_web; then
  die 'Hub установлен, но путь/HTTPS не настроен. Повторите эту команду с --configure-web --public-address ДОМЕН_ИЛИ_IP; доступ через SSH сохранён.'
fi

say 'Установка завершена. Дополнительные серверы подключаются из панели или приложения по SSH.'
if [[ -z $public_address ]]; then
  say 'Публичный адрес не указан. UI запущен, но доступен только через SSH-туннель.'
  say 'Чтобы включить публичный HTTPS позже, используйте этот же скрипт с --configure-web --public-address ДОМЕН_ИЛИ_IP.'
  say 'Для автоматического SSH-проброса добавьте этот сервер в Connect или мобильном приложении и выберите открытие панели.'
  say "Для браузера на компьютере: ssh -L 8766:127.0.0.1:8766 SSH_USER@SERVER_ADDRESS; затем откройте http://127.0.0.1:8766${panel_path}"
fi
