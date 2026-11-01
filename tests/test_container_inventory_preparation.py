# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Execute the real inventory preparation and preflight against private paths."""
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / 'run.sh').read_text()
START = SOURCE.index('container_inventory_preflight() {')
FUNCTIONS = SOURCE[START:SOURCE.index('\nif (( with_containers || containers_disable_requested )); then', START)]


@unittest.skipUnless(os.name == 'posix' and shutil.which('bash'), 'POSIX Bash fixtures required')
class ContainerInventoryPreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.lib = self.root / 'var/lib'
        self.etc = self.root / 'etc/sovagrid'
        self.units = self.root / 'etc/systemd/system'
        for path in (self.lib, self.etc, self.units): path.mkdir(parents=True)
        self.etc.chmod(0o750)
        self.directory = self.lib / 'sovagrid-containers'
        self.receipt = self.directory / '.prepared-by-run-sh'
        self.marker = self.etc / '.containers-managed-by-run-sh'
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        # Model root/sovagrid identities while keeping every real operation
        # unprivileged. Modes, types, inodes and link counts remain real.
        self.tool('stat', r'''
import json, os, pathlib, stat, sys
path=pathlib.Path(sys.argv[-1]); info=path.lstat()
owner='root' if info.st_uid==os.getuid() else 'foreign'
group='sovagrid' if path.name in ('sovagrid-containers','sovagrid','snapshot.json') or path.name.startswith('.sovagrid-container-prepare.') else 'root'
if path.name=='.containers-managed-by-run-sh' or path.name.startswith('.containers-marker.'):
 group=os.environ.get('TEST_MARKER_DEFAULT_GROUP','root')
trace=pathlib.Path(os.environ['TEST_TRACE'])
if trace.exists():
 for line in trace.read_text().splitlines():
  event=json.loads(line)
  if event[:2]==['chown',file_identity(path)]: owner,group=event[2].split(':')
if str(path)==os.environ.get('TEST_BAD_OWNER'): owner='foreign'
if str(path)==os.environ.get('TEST_BAD_GROUP'): group='foreign'
values={'%U':owner,'%G':group,'%a':format(stat.S_IMODE(info.st_mode),'o'),'%h':str(info.st_nlink)}
print(':'.join(values[part] for part in sys.argv[2].split(':')))
''')
        self.tool('find', r'''
import pathlib, stat, sys
path=pathlib.Path(sys.argv[1])
if '-perm' in sys.argv:
 if stat.S_IMODE(path.stat().st_mode)&0o022: print(path)
else:
 for child in path.iterdir():
  if child.name not in ('snapshot.json','.prepared-by-run-sh'):
   print(child); break
''')
        self.tool('chown', r'''
import json, os, pathlib, sys
with open(os.environ['TEST_TRACE'],'a') as stream:
 stream.write(json.dumps(['chown',file_identity(pathlib.Path(sys.argv[-1])),sys.argv[1]])+'\n')
''')
        self.tool('python-sync', r'''
import json, os, pathlib, subprocess, sys
result=subprocess.run([sys.executable,*sys.argv[1:]],input=sys.stdin.buffer.read())
if result.returncode: sys.exit(result.returncode)
with open(os.environ['TEST_TRACE'],'a') as stream:
 for name in sys.argv[sys.argv.index('-')+1:]:
  stream.write(json.dumps(['sync',file_identity(pathlib.Path(name))])+'\n')
if os.environ.get('TEST_FAIL_MARKER_SYNC')=='1' and any(path.endswith('/.containers-managed-by-run-sh') for path in sys.argv): sys.exit(98)
''')
        self.tool('mv', r'''
import json, os, pathlib, stat, sys
source,destination=map(pathlib.Path,sys.argv[-2:])
if os.environ.get('TEST_RACE_TARGET')=='1':
 destination.mkdir(mode=0o750); (destination/'foreign').write_text('preserve')
if destination.name=='.containers-managed-by-run-sh':
 events=[json.loads(line) for line in pathlib.Path(os.environ['TEST_TRACE']).read_text().splitlines()]
 inode=file_identity(source)
 assert ['chown',inode,'root:root'] in events and ['sync',inode] in events
 assert events.index(['chown',inode,'root:root']) < events.index(['sync',inode])
 assert stat.S_IMODE(source.stat().st_mode)==0o600
 if os.environ.get('TEST_RACE_MARKER')=='1': destination.write_text('foreign marker')
 if os.environ.get('TEST_FAIL_MARKER_PUBLISH')=='1': sys.exit(99)
if destination.exists() or destination.is_symlink(): sys.exit(0)
os.rename(source,destination)
with open(os.environ['TEST_TRACE'],'a') as stream:
 stream.write(json.dumps(['publish',file_identity(destination)])+'\n')
if os.environ.get('TEST_FAIL_AFTER_PUBLISH')=='1': sys.exit(97)
''')
        self.functions = FUNCTIONS.replace('/etc/systemd/system', str(self.units)).replace('/etc/sovagrid', str(self.etc))
        self.functions = self.functions.replace('/var/lib', str(self.lib)).replace('/usr/bin/python3', shlex.quote(str(self.bin / 'python-sync')))

    def tool(self, name, code):
        path = self.bin / name
        path.write_text('#!' + sys.executable + ' -B\n' +
                        'def file_identity(path):\n'
                        ' info=path.stat()\n'
                        ' return f"{info.st_dev}:{info.st_ino}:{info.st_mtime_ns}:{info.st_size}"\n' + code)
        path.chmod(0o755)

    def run_shell(self, operation, **environment):
        script = ('set -euo pipefail\numask 077\ncontainers_disable_requested=${TEST_DISABLE:-0}\n'
                  'die() { printf "%s\\n" "$*" >&2; exit 1; }\n' + self.functions + '\n' + operation)
        return subprocess.run(['bash', '-c', script], text=True, capture_output=True, timeout=15,
                              env=dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                                       TEST_TRACE=str(self.root / 'trace'), PYTHONDONTWRITEBYTECODE='1', **environment))

    def prepare(self):
        result = self.run_shell('container_inventory_prepare')
        self.assertEqual(result.returncode, 0, result.stderr)

    def pending(self):
        result = self.run_shell('container_inventory_prepare', TEST_FAIL_AFTER_PUBLISH='1')
        self.assertEqual(result.returncode, 97, result.stderr)
        self.assertTrue(self.receipt.is_file())
        self.assertFalse(self.marker.exists())

    def test_retry_after_interruption_between_directory_and_marker_publication(self):
        self.pending()
        inode = self.directory.stat().st_ino
        self.assertEqual(self.run_shell('container_inventory_preflight').returncode, 0)
        self.prepare()
        self.assertEqual(self.directory.stat().st_ino, inode)
        self.assertEqual(self.marker.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(self.directory.iterdir()), [])
        self.assertEqual(list(self.units.iterdir()), [])
        self.assertEqual(list(self.lib.glob('.sovagrid-container-prepare.*')), [])

    def test_later_ordinary_failure_is_retryable_without_claiming_activation(self):
        result = self.run_shell('container_inventory_prepare\nexit 96')
        self.assertEqual(result.returncode, 96, result.stderr)
        self.prepare()
        self.assertFalse(self.receipt.exists())
        self.assertFalse((self.directory / 'snapshot.json').exists())
        self.assertEqual(list(self.units.iterdir()), [])

    def test_interruption_after_marker_publication_can_resume_disable_preparation(self):
        result = self.run_shell('container_inventory_prepare', TEST_FAIL_MARKER_SYNC='1')
        self.assertEqual(result.returncode, 98, result.stderr)
        self.assertTrue(self.marker.is_file())
        self.assertTrue(self.receipt.is_file())
        result = self.run_shell('container_inventory_prepare', TEST_DISABLE='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.receipt.exists())
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_marker_metadata_is_ready_and_synced_before_publish_with_nonroot_egid(self):
        result = self.run_shell('container_inventory_prepare', TEST_MARKER_DEFAULT_GROUP='nonroot')
        self.assertEqual(result.returncode, 0, result.stderr)
        events = [json.loads(line) for line in (self.root / 'trace').read_text().splitlines()]
        info = self.marker.stat()
        inode = f'{info.st_dev}:{info.st_ino}:{info.st_mtime_ns}:{info.st_size}'
        self.assertLess(events.index(['chown', inode, 'root:root']), events.index(['sync', inode]))
        self.assertLess(events.index(['sync', inode]), events.index(['publish', inode]))
        self.assertEqual(self.marker.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(self.etc.glob('.containers-marker.*')), [])

    def test_marker_race_preserves_foreign_target_and_cleans_private_staging(self):
        result = self.run_shell('container_inventory_prepare', TEST_RACE_MARKER='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.marker.read_text(), 'foreign marker')
        self.assertTrue(self.receipt.is_file())
        self.assertEqual(list(self.etc.glob('.containers-marker.*')), [])

    def test_failed_marker_publish_cleans_staging_and_remains_retryable(self):
        result = self.run_shell('container_inventory_prepare', TEST_FAIL_MARKER_PUBLISH='1')
        self.assertEqual(result.returncode, 99, result.stderr)
        self.assertFalse(self.marker.exists())
        self.assertTrue(self.receipt.is_file())
        self.assertEqual(list(self.etc.glob('.containers-marker.*')), [])
        self.prepare()

    def test_preexisting_unmarked_directory_or_units_remain_refused(self):
        self.directory.mkdir(mode=0o750)
        for operation in ('container_inventory_preflight', 'container_inventory_prepare'):
            self.assertNotEqual(self.run_shell(operation).returncode, 0)
        self.assertEqual(list(self.directory.iterdir()), [])
        self.assertFalse(self.marker.exists())
        self.directory.rmdir()
        (self.units / 'sovagrid-container-inventory.service').write_text('foreign')
        self.assertNotEqual(self.run_shell('container_inventory_prepare').returncode, 0)
        self.assertFalse(self.directory.exists())

    def test_pending_units_and_tampered_receipt_are_refused(self):
        self.pending()
        unit = self.units / 'sovagrid-container-inventory.service'
        unit.write_text('foreign')
        self.assertNotEqual(self.run_shell('container_inventory_prepare').returncode, 0)
        unit.unlink()
        original = self.receipt.read_bytes()
        for content in (b'foreign', original + b'\n'):
            self.receipt.write_bytes(content)
            self.assertNotEqual(self.run_shell('container_inventory_preflight').returncode, 0)
        self.receipt.write_bytes(original)
        for variable in ('TEST_BAD_OWNER', 'TEST_BAD_GROUP'):
            self.assertNotEqual(self.run_shell('container_inventory_prepare', **{variable: str(self.receipt)}).returncode, 0)
        self.receipt.chmod(0o640)
        self.assertNotEqual(self.run_shell('container_inventory_prepare').returncode, 0)
        self.receipt.chmod(0o600)
        os.link(self.receipt, self.root / 'receipt-alias')
        self.assertNotEqual(self.run_shell('container_inventory_prepare').returncode, 0)
        self.assertFalse(self.marker.exists())

    def test_symlink_and_foreign_directory_metadata_are_refused(self):
        foreign = self.root / 'foreign'
        foreign.mkdir(mode=0o750)
        self.directory.symlink_to(foreign, target_is_directory=True)
        self.assertNotEqual(self.run_shell('container_inventory_prepare').returncode, 0)
        self.directory.unlink()
        self.pending()
        for variable in ('TEST_BAD_OWNER', 'TEST_BAD_GROUP'):
            self.assertNotEqual(self.run_shell('container_inventory_prepare', **{variable: str(self.directory)}).returncode, 0)
        self.directory.chmod(0o770)
        self.assertNotEqual(self.run_shell('container_inventory_prepare').returncode, 0)
        self.directory.chmod(0o750)
        self.receipt.unlink()
        self.receipt.symlink_to(self.root / 'absent')
        self.assertNotEqual(self.run_shell('container_inventory_prepare').returncode, 0)

    def test_racing_target_is_never_replaced_or_adopted(self):
        result = self.run_shell('container_inventory_prepare', TEST_RACE_TARGET='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.directory / 'foreign').read_text(), 'preserve')
        self.assertFalse(self.marker.exists())
        self.assertEqual(list(self.lib.glob('.sovagrid-container-prepare.*')), [])

    def test_reused_inode_with_stale_receipt_generation_does_not_change_snapshot_group(self):
        self.prepare()
        snapshot = self.directory / 'snapshot.json'
        snapshot.write_text('{}')
        snapshot.chmod(0o640)
        info = snapshot.stat()
        stale = f'{info.st_dev}:{info.st_ino}:{info.st_mtime_ns - 1}:29'
        with (self.root / 'trace').open('a') as stream:
            stream.write(json.dumps(['chown', stale, 'root:root']) + '\n')
        self.prepare()

    def test_marker_and_legacy_managed_snapshot_validation(self):
        self.prepare()
        snapshot = self.directory / 'snapshot.json'
        snapshot.write_text('{}')
        snapshot.chmod(0o640)
        self.prepare()
        self.assertEqual(list(self.directory.iterdir()), [snapshot])
        for variable in ('TEST_BAD_OWNER', 'TEST_BAD_GROUP'):
            self.assertNotEqual(self.run_shell('container_inventory_preflight', **{variable: str(self.marker)}).returncode, 0)
        self.marker.chmod(0o644)
        self.assertNotEqual(self.run_shell('container_inventory_preflight').returncode, 0)
        self.marker.chmod(0o600)
        self.marker.unlink()
        self.marker.symlink_to(self.root / 'absent')
        self.assertNotEqual(self.run_shell('container_inventory_prepare').returncode, 0)


if __name__ == '__main__': unittest.main()
