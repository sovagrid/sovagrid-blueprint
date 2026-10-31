# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Root enrollment boundary tests; fake filesystem, real bounded subprocesses."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import subprocess
import unittest
import uuid
from types import SimpleNamespace
from unittest import mock

import package_server

SOURCE = Path(__file__).resolve().parents[1] / "deploy/remote_agent.py"
spec = importlib.util.spec_from_file_location("remote_agent_helper", SOURCE)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def ssh_key():
    raw = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + bytes(range(32))
    return "ssh-ed25519 " + base64.b64encode(raw).decode()


class ProtocolTests(unittest.TestCase):
    def test_package_and_enrollment_share_source_path_rules(self):
        for name, expected in (
                ("sovagrid-blueprint/deploy/sovagrid-external-agent-apply@.service", True),
                ("sovagrid-agent/README.md", True),
                ("sovagrid-vpn/sovagrid_vpn/__init__.py", True),
                ("sovagrid-agent//README.md", False),
                ("sovagrid-agent/../README.md", False),
                ("sovagrid-agent/.hidden/./README.md", False),
                ("sovagrid-agent/тест.py", False),
                ("sovagrid-agent/README.md/", False),
                ("sovagrid-agent/README+unsafe.md", False)):
            with self.subTest(name=name):
                self.assertEqual(package_server.valid_manifest_source_name(name), expected)
                self.assertEqual(helper.valid_manifest_source_name(name), expected)

    def test_strict_actions_protocol_fields_and_canonical_ids(self):
        request_id = str(uuid.uuid4())
        good = {"protocol": 1, "request_id": request_id}
        self.assertEqual(helper.validate_request("target-preview", good), good)
        for action, value in (("unknown", good), ("target-preview", dict(good, protocol=True)),
                              ("target-preview", dict(good, request_id=request_id.upper())),
                              ("target-preview", dict(good, password="CANARY")),
                              ("hub-preview", good), ("target-preview", {"protocol":1})):
            with self.subTest(action=action, value=value), self.assertRaises(helper.Refuse):
                helper.validate_request(action, value)
        with self.assertRaises(helper.Refuse):
            json.loads('{"protocol":1,"protocol":1}', object_pairs_hook=helper.unique_object)

    def test_public_key_does_not_accept_options_comments_or_extra_lines(self):
        value, fingerprint = helper.public_key(ssh_key())
        self.assertEqual(value, ssh_key())
        self.assertRegex(fingerprint, r"^SHA256:[A-Za-z0-9+/]{43}$")
        for value in (ssh_key()+"\n", ssh_key()+" comment", "command=bad "+ssh_key(),
                      ssh_key().replace("ssh-ed25519", "ssh-rsa"), "ssh-ed25519 YQ=="):
            with self.subTest(value=value), self.assertRaises(helper.Refuse):
                helper.public_key(value)
        self.assertEqual(len(helper.username(str(uuid.uuid4()))), 30)
        self.assertNotEqual(helper.username(str(uuid.uuid4())), helper.username(str(uuid.uuid4())))

    def test_hub_helper_never_accepts_bearer_or_digest(self):
        ids = {"protocol":1, "enrollment_id":str(uuid.uuid4()), "server_id":str(uuid.uuid4()),
               "expected":dict.fromkeys(helper.CAS_FIELDS, "a"*64), "ssh_public_key":ssh_key(),
               "ssh_key_fingerprint":helper.public_key(ssh_key())[1]}
        helper.validate_request("hub-authorize", ids)
        for field in ("agent_token", "agent_token_sha256", "password", "source_path", "username"):
            with self.subTest(field=field), self.assertRaises(helper.Refuse):
                helper.validate_request("hub-authorize", dict(ids, **{field:"CANARY"}))

    def test_mapped_forbidden_addresses_and_nonstring_host_fail_before_ca(self):
        base = {"protocol":1,"request_id":str(uuid.uuid4()),"enrollment_id":str(uuid.uuid4()),
                "server_id":str(uuid.uuid4()),"expected":dict.fromkeys(helper.CAS_FIELDS,"a"*64),
                "hub_port":22,"local_port":18767,"hub_host_key":ssh_key(),"hub_ca_pem":"PUBLIC"}
        for host in (True,1,2130706433,"::ffff:127.0.0.1","::ffff:0.0.0.0","::ffff:224.0.0.1","127.0.0.1","::1"):
            with self.subTest(host=host), mock.patch.object(helper.ssl,"create_default_context") as context:
                with self.assertRaises(helper.Refuse):
                    helper.validate_request("target-transport",dict(base,hub_host=host))
                context.assert_not_called()

    def test_cli_error_never_echoes_request_or_secret(self):
        canary="DO_NOT_PRINT_PRIVATE_ENROLLMENT_CANARY"
        raw=json.dumps({"protocol":1,"password":canary}).encode()
        completed=subprocess.run([sys.executable,"-I",str(SOURCE),"hub-preview"],input=raw,capture_output=True)
        self.assertNotEqual(completed.returncode,0)
        self.assertEqual(json.loads(completed.stdout),{"protocol":1,"ok":False,"error":"INVALID_REQUEST"})
        self.assertNotIn(canary.encode(),completed.stdout+completed.stderr)


class FilesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.files = helper.Files(self.root, owner=os.getuid())

    def tearDown(self):
        self.temp.cleanup()

    def test_atomic_private_write_and_path_conflicts(self):
        self.files.mkdir("/state")
        self.files.write("/state/test", b"private fixture")
        self.assertEqual(self.files.read("/state/test", private=True), b"private fixture")
        self.assertEqual((self.root/"state/test").stat().st_mode & 0o777, 0o600)
        self.files.write("/state/test", b"replacement")
        self.assertEqual(self.files.read("/state/test"), b"replacement")
        os.link(self.root/"state/test", self.root/"state/hard")
        with self.assertRaises(helper.Refuse):
            self.files.read("/state/test")
        (self.root/"state/link").symlink_to("test")
        with self.assertRaises(helper.Refuse):
            self.files.write("/state/link", b"overwrite")
        with self.assertRaises(helper.Refuse):
            self.files.path("/state/../escape")
        self.assertFalse((self.root/"escape").exists())

    def test_symlink_or_writable_ancestor_is_not_followed(self):
        self.files.mkdir("/real", 0o755)
        (self.root/"alias").symlink_to("real", target_is_directory=True)
        with self.assertRaises(helper.Refuse):
            self.files.inspect("/alias", directory=True)
        (self.root/"real").chmod(0o777)
        with self.assertRaises(helper.Refuse):
            self.files.read("/real/missing", missing=True)

    def test_fixed_root_owned_sticky_staging_parent_is_supported(self):
        self.files.mkdir("/var", 0o755)
        (self.root/"var/tmp").mkdir(mode=0o1777)
        (self.root/"var/tmp").chmod(0o1777)
        self.files.mkdir("/var/tmp/sovagrid-agent-enroll.ABCDEFGH", 0o700)
        self.files.inspect("/var/tmp/sovagrid-agent-enroll.ABCDEFGH", directory=True, private=True)

    def test_new_directory_modes_survive_private_umask_without_repairing_existing_paths(self):
        previous = os.umask(0o077)
        try:
            self.files.mkdir("/etc/service", 0o755)
            self.files.mkdir("/private", 0o700)
            for path in ("/etc", "/etc/service"):
                self.assertEqual(self.files.path(path).stat().st_mode & 0o777, 0o755)
            self.assertEqual(self.files.path("/private").stat().st_mode & 0o777, 0o700)
            with self.assertRaises(helper.Refuse):
                self.files.mkdir("/private", 0o755)
            self.assertEqual(self.files.path("/private").stat().st_mode & 0o777, 0o700)
        finally:
            os.umask(previous)

    def source_fixture(self):
        root = "/opt/sovagrid-src"
        self.files.mkdir(root, 0o755)
        hashes = {}
        counts = {}
        for component in helper.COMPONENTS:
            self.files.mkdir(root+"/"+component, 0o755)
            name = helper.SELF_NAME if component == "sovagrid-blueprint" else component+"/LICENSE"
            parent = str(Path(root+"/"+name).parent)
            self.files.mkdir(parent, 0o755)
            data = SOURCE.read_bytes() if component == "sovagrid-blueprint" else b"test license\n"
            self.files.write(root+"/"+name, data, mode=0o644)
            hashes[name] = helper.digest(data)
            counts[component] = {"commit":"a"*40,"file_count":1}
        for name in helper.REQUIRED_SOURCE - set(hashes):
            self.files.mkdir(str(Path(root+"/"+name).parent),0o755)
            self.files.write(root+"/"+name,b"fixture\n",mode=0o644)
            hashes[name]=helper.digest(b"fixture\n")
        for component in counts:
            counts[component]["file_count"]=sum(name.startswith(component+"/") for name in hashes)
        raw = helper.encode({"format":1,"components":counts,"sha256":hashes})
        self.files.write(root+"/sovagrid-bundle.json", raw, mode=0o644)
        return helper.Source(self.files, root), raw

    def test_exact_manifest_files_hashes_and_unexpected_entries(self):
        source, raw = self.source_fixture()
        self.assertEqual(source.verify()[0], helper.digest(raw))
        self.files.write("/opt/sovagrid-src/sovagrid-agent/extra.py", b"extra", mode=0o644)
        with self.assertRaises(helper.Refuse):
            source.verify()
        (self.root/"opt/sovagrid-src/sovagrid-agent/extra.py").unlink()
        self.files.write("/opt/sovagrid-src/sovagrid-agent/LICENSE", b"tampered", mode=0o644)
        with self.assertRaises(helper.Refuse):
            source.verify()

    def test_manifest_accepts_systemd_template_unit_and_rejects_empty_segments(self):
        source, _ = self.source_fixture()
        root = "/opt/sovagrid-src"
        unit = "sovagrid-blueprint/deploy/sovagrid-external-agent-apply@.service"
        self.files.write(root + "/" + unit, b"[Unit]\nDescription=fixture\n", mode=0o644)
        manifest = json.loads(self.files.read(root + "/sovagrid-bundle.json"))
        manifest["sha256"][unit] = helper.digest(b"[Unit]\nDescription=fixture\n")
        manifest["components"]["sovagrid-blueprint"]["file_count"] += 1
        self.files.write(root + "/sovagrid-bundle.json", helper.encode(manifest), mode=0o644)
        source.verify()
        manifest["sha256"][unit.replace("/deploy/", "//deploy/")] = manifest["sha256"].pop(unit)
        self.files.write(root + "/sovagrid-bundle.json", helper.encode(manifest), mode=0o644)
        with self.assertRaises(helper.Refuse) as error:
            source.verify()
        self.assertEqual(error.exception.code, "SOURCE_UNTRUSTED")

    def test_nested_match_include_changes_policy_snapshot(self):
        self.files.mkdir("/etc/ssh",0o755)
        self.files.write("/etc/ssh/sshd_config",b"Include /etc/ssh/extra-policy\n",mode=0o644)
        self.files.write("/etc/ssh/extra-policy",b"Match Group sovagrid-tunnel\n PermitOpen 127.0.0.1:8767\n",mode=0o644)
        commands=mock.Mock()
        commands.run.return_value=(0,b"maxsessions 10\n") # -T without -C misses Match.
        enrollment=helper.Enrollment(root=self.root,owner=os.getuid(),commands=commands)
        before=enrollment.policy_snapshot("hub")
        self.files.write("/etc/ssh/extra-policy",b"Match Group sovagrid-tunnel\n PermitOpen any\n",mode=0o644)
        after=enrollment.policy_snapshot("hub")
        self.assertNotEqual(before,after)
        self.files.write("/etc/ssh/extra-policy",b"Match Group sovagrid-tunnel LocalPort 22222\n AllowTcpForwarding yes\n",mode=0o644)
        with self.assertRaises(helper.Refuse):enrollment.policy_snapshot("hub")
        self.files.write("/etc/ssh/extra-policy",b"Include /etc/ssh/sshd_config\n",mode=0o644)
        with self.assertRaises(helper.Refuse):
            enrollment.policy_snapshot("hub")

    def test_supported_ubuntu26_and_loadcredential_gate(self):
        self.files.mkdir("/usr/lib",0o755)
        self.files.write("/usr/lib/os-release",b'ID=ubuntu\nVERSION_ID="26.04"\n',mode=0o644)
        self.files.mkdir("/run/systemd/system",0o755)
        commands=mock.Mock()
        commands.run.return_value=(0,b"systemd 259 (259.1)\n")
        enrollment=helper.Enrollment(root=self.root,owner=os.getuid(),commands=commands)
        self.assertEqual(enrollment.platform()["ubuntu_version"],"26.04")
        self.assertEqual(enrollment.platform()["systemd_version"],"259")
        commands.run.return_value=(0,b"systemd 246\n")
        with self.assertRaises(helper.Refuse):
            enrollment.platform()

    def test_real_key_target_prepare_is_repeatable_and_never_exports_secrets(self):
        source, _ = self.source_fixture()
        root = "/opt/sovagrid-src"
        manifest = json.loads(self.files.read(root+"/sovagrid-bundle.json"))
        for relative in ("sovagrid_agent/__main__.py","NOTICE","ATTRIBUTION.md","deploy/sovagrid-agent.service"):
            path=root+"/sovagrid-agent/"+relative
            self.files.mkdir(str(Path(path).parent),0o755)
            data=(b"[Unit]\nDescription=fixture\n[Service]\nExecStart=/usr/bin/true\n" if relative.endswith(".service") else b"fixture\n")
            self.files.write(path,data,mode=0o644)
            manifest["sha256"]["sovagrid-agent/"+relative]=helper.digest(data)
        manifest["components"]["sovagrid-agent"]["file_count"]=5
        self.files.write(root+"/sovagrid-bundle.json",helper.encode(manifest),mode=0o644)
        self.files.mkdir("/var/tmp/sovagrid-agent-enroll.12345678",0o700)
        stage="/var/tmp/sovagrid-agent-enroll.12345678/source"
        self.files.path(root).rename(self.files.path(stage))
        self.files.mkdir("/usr/lib",0o755)
        self.files.write("/usr/lib/os-release",b'ID=ubuntu\nVERSION_ID="26.04"\n',mode=0o644)
        self.files.mkdir("/run/systemd/system",0o755)
        entries={};groups={};calls=[];real=helper.Commands();files=self.files
        def lookup(name):
            if name not in entries:raise KeyError(name)
            return entries[name]
        def group_lookup(name):
            if name not in groups:raise KeyError(name)
            return groups[name]
        def command(argv,**options):
            calls.append(argv)
            if argv[:2]==["/usr/bin/systemctl","--version"]:return 0,b"systemd 259\n"
            if argv[0]=="/usr/bin/dpkg-query":return 0,b"install ok installed\n"*3
            if argv[0]=="/usr/sbin/useradd":
                comment = argv[argv.index("--comment")+1]
                self.assertRegex(comment, r"^sovagrid-[0-9a-f-]{36}-(agent|tunnel)$")
                self.assertFalse(any(character in comment for character in ":\r\n"))
                name=argv[-1];gid=20000+len(entries) if os.getuid()==0 else os.getgid()
                entries[name]=SimpleNamespace(pw_uid=5001+len(entries),pw_gid=gid,pw_dir=argv[argv.index("--home-dir")+1],
                                               pw_shell="/usr/sbin/nologin",pw_gecos=argv[argv.index("--comment")+1])
                groups[name]=SimpleNamespace(gr_name=name,gr_gid=gid,gr_mem=[])
                return 0,b""
            if argv[0]=="/usr/sbin/userdel":
                entries.pop(argv[-1]);groups.pop(argv[-1],None)
                return 0,b""
            if argv[0]=="/usr/sbin/groupdel":
                groups.pop(argv[-1],None)
                return 0,b""
            if argv[:2]==["/usr/bin/systemctl","daemon-reload"]:return 0,b""
            if argv[0]=="/usr/bin/ssh-keygen":
                args=list(argv);i=args.index("-f")+1;args[i]=str(files.path(args[i]))
                return real.run(args,**options)
            raise AssertionError("Unexpected fixed command: "+repr(argv))
        runner=helper.Enrollment(root=self.root,owner=os.getuid(),executable=stage+"/"+helper.SELF_NAME,
                                 commands=SimpleNamespace(run=command))
        request_id=str(uuid.uuid4())
        with mock.patch.object(helper.pwd,"getpwnam",side_effect=lookup), mock.patch.object(helper.grp,"getgrnam",side_effect=group_lookup), mock.patch.object(helper.os,"getgrouplist",side_effect=lambda n,g:[g]):
            first=runner.target_prepare({"protocol":1,"request_id":request_id,"expected":runner.cas("target")})
            second=runner.target_prepare({"protocol":1,"request_id":request_id,"expected":runner.cas("target")})
            self.assertEqual(first["target"],second["target"])
            self.assertEqual(first["target"]["phase"],"prepared")
            token=self.files.read("/etc/sovagrid/agent.token").strip()
            private=self.files.read("/etc/sovagrid-agent-tunnel/id_ed25519",private=True)
            self.assertTrue(token not in helper.encode(first),"fixture bearer must not appear in a reply")
            self.assertTrue(private not in helper.encode(first),"fixture private key must not appear in a reply")
            self.assertEqual(sum("-q" in args for args in calls if args[0]=="/usr/bin/ssh-keygen"),1)
            self.assertNotEqual(entries["sovagrid"].pw_uid,entries["sovagrid-tunnel"].pw_uid)
            # Pending cancellation cleanup, lost cleanup response retry, then
            # an explicitly new operation must work. The old operation must
            # never mutate that replacement even with a freshly read CAS.
            installed=helper.Enrollment(root=self.root,owner=os.getuid(),executable=helper.TARGET_HELPER,commands=runner.commands)
            installed.source("target")
            valid_state=runner.target_state(request_id)
            corrupted=dict(valid_state,source_files={})
            runner.save_state("target",corrupted)
            with self.assertRaises(helper.Refuse):installed.source("target")
            runner.save_state("target",valid_state)
            old_identity={key:first["target"][key] for key in ("request_id","enrollment_id","server_id")}
            state=runner.target_state(request_id);state["phase"]="registered";runner.save_state("target",state)
            cancelled={"id":old_identity["enrollment_id"],"server_id":old_identity["server_id"],"name":"fixture",
                       "state":"cancelled","revision":2,"created_at":1,"last_seen":None}
            remove={"protocol":1,**old_identity,"registration":cancelled,"expected":runner.cas("target")}
            self.assertTrue(runner.target_remove(remove)["removed"])
            remove["expected"]=runner.cas("target")
            self.assertTrue(runner.target_remove(remove)["removed"])
            self.assertIsNone(runner.target_state(request_id))
            new_request=str(uuid.uuid4())
            fresh=runner.target_prepare({"protocol":1,"request_id":new_request,"expected":runner.cas("target")})
            self.assertNotEqual(fresh["target"]["server_id"],old_identity["server_id"])
            before=self.files.read(helper.TARGET_STATE,private=True)
            remove["expected"]=runner.cas("target")
            with self.assertRaises(helper.Refuse):runner.target_remove(remove)
            self.assertEqual(self.files.read(helper.TARGET_STATE,private=True),before)
            request_id=new_request
            self.files.path("/etc/sovagrid-agent-tunnel/id_ed25519").unlink()
            with self.assertRaises(helper.Refuse):
                runner.target_prepare({"protocol":1,"request_id":request_id,"expected":runner.cas("target")})
            self.assertEqual(sum("-q" in args for args in calls if args[0]=="/usr/bin/ssh-keygen"),2)

    def test_kernel_uid_field_cannot_be_spoofed_by_process_name(self):
        self.files.mkdir("/proc",0o755)
        for pid,uid,spoof in ((101,1000,True),(102,5005,False),(103,0,True)):
            self.files.mkdir("/proc/"+str(pid),0o755)
            raw=("Name:\tfixture\n"+("Uid:\t5005\t5005\t5005\t5005\n" if spoof else "")
                 +f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n").encode()
            self.files.write(f"/proc/{pid}/status",raw,mode=0o644)
            tail=["S"]+["0"]*18+[str(pid+1000)]
            self.files.write(f"/proc/{pid}/stat",(f"{pid} (fixture) "+" ".join(tail)).encode(),mode=0o644)
        runner=helper.Enrollment(root=self.root,owner=os.getuid())
        with mock.patch.object(helper.sys,"platform","linux"):
            self.assertEqual(runner.process_snapshot(5005),{102:(1102,"S")})
            with self.assertRaises(helper.Refuse):runner.process_snapshot(0)

    def test_revoke_signals_only_current_uid_and_start_time(self):
        record={"uid":5005,"gid":5005,"comment":"own operation","home":"/var/empty/own"}
        entry=SimpleNamespace(pw_uid=5005,pw_gid=5005,pw_gecos=record["comment"],pw_dir=record["home"],pw_shell="/usr/sbin/nologin")
        runner=helper.Enrollment(root=self.root,owner=os.getuid())
        runner.process_snapshot=mock.Mock(side_effect=[{101:(1,"S"),102:(2,"S")},{101:(9,"S"),102:(2,"S")},{102:(2,"S")},{}])
        kill=mock.Mock()
        with mock.patch.object(helper.pwd,"getpwnam",return_value=entry), mock.patch.object(helper.os,"getgrouplist",return_value=[5005]), mock.patch.object(helper,"os",SimpleNamespace(kill=kill,getgrouplist=lambda n,g:[g])):
            runner.terminate_uid("own",record)
        kill.assert_called_once_with(102,helper.signal.SIGTERM)


class StateCapacityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.runner = helper.Enrollment(root=Path(self.temp.name), owner=os.getuid(), commands=mock.Mock())
        self.runner.check_cas = mock.Mock()
        self.runner.cas = mock.Mock(return_value=dict.fromkeys(helper.CAS_FIELDS, "a" * 64))
        self.files = self.runner.files
        self.files.mkdir(helper.HUB_STATE_DIR, 0o700)
        self.files.mkdir(helper.TARGET_STATE_DIR, 0o700)

    def tearDown(self):
        self.temp.cleanup()

    def hub_state(self, total, active):
        enrollments = {}
        for index in range(total):
            eid, sid = str(uuid.UUID(int=index + 1)), str(uuid.UUID(int=index + 10001))
            enrollments[eid] = {"enrollment_id": eid, "server_id": sid, "username": helper.username(sid),
                                "ssh_public_key": ssh_key(), "ssh_key_fingerprint": helper.public_key(ssh_key())[1],
                                "revoked": index >= active}
        state = {"protocol": 1, "kind": "hub", "enrollments": enrollments, "accounts": {},
                 "owned_files": {}, "owned_directories": {}, "pending_writes": {}}
        self.runner.save_state("hub", state)
        return state

    def authorize_request(self, entry=None):
        entry = entry or {"enrollment_id": str(uuid.uuid4()), "server_id": str(uuid.uuid4()),
                          "ssh_public_key": ssh_key(), "ssh_key_fingerprint": helper.public_key(ssh_key())[1]}
        return {"protocol": 1, "expected": dict.fromkeys(helper.CAS_FIELDS, "a" * 64),
                **{field: entry[field] for field in ("enrollment_id", "server_id", "ssh_public_key", "ssh_key_fingerprint")}}

    def test_large_hub_journal_remains_readable_and_revocable(self):
        state = self.hub_state(helper.MAX_HUB_ENROLLMENTS, 1)
        self.assertGreater(self.files.path(helper.HUB_STATE).stat().st_size, helper.MAX_RPC)
        entry = next(iter(state["enrollments"].values()))
        status = self.runner.hub_status(entry)
        self.assertFalse(status["authorized"])
        self.assertEqual(status["ssh_key_fingerprint"], entry["ssh_key_fingerprint"])
        result = self.runner.hub_revoke(self.authorize_request(entry))
        self.assertTrue(result["revoked"])
        self.assertTrue(self.runner.hub_state()["enrollments"][entry["enrollment_id"]]["revoked"])
        self.runner.commands.run.assert_not_called()

    def test_new_authorization_at_either_limit_has_no_state_or_resource_writes(self):
        for total, active in ((helper.MAX_HUB_ENROLLMENTS, 0),
                              (helper.MAX_HUB_ACTIVE_ENROLLMENTS, helper.MAX_HUB_ACTIVE_ENROLLMENTS)):
            with self.subTest(total=total, active=active):
                self.hub_state(total, active)
                before = self.files.read(helper.HUB_STATE, limit=helper.MAX_STATE)
                with mock.patch.object(self.files, "write", wraps=self.files.write) as write, \
                        mock.patch.object(self.runner, "effective") as effective:
                    with self.assertRaises(helper.Refuse) as error:
                        self.runner.hub_authorize(self.authorize_request())
                self.assertEqual(error.exception.code, "STATE_CONFLICT")
                self.assertEqual(self.files.read(helper.HUB_STATE, limit=helper.MAX_STATE), before)
                write.assert_not_called()
                effective.assert_not_called()
                self.runner.commands.run.assert_not_called()

    def test_existing_exact_authorization_can_retry_at_both_limits(self):
        state = self.hub_state(helper.MAX_HUB_ENROLLMENTS, helper.MAX_HUB_ACTIVE_ENROLLMENTS)
        entry = next(iter(state["enrollments"].values()))
        self.files.mkdir("/etc/ssh/sshd_config.d", 0o755)
        before = self.files.read(helper.HUB_STATE, limit=helper.MAX_STATE)
        with mock.patch.object(self.runner, "effective", return_value={}), \
                mock.patch.object(self.runner, "hub_group"), mock.patch.object(self.runner, "account"), \
                mock.patch.object(self.runner, "owned_directory"), mock.patch.object(self.runner, "owned_write"), \
                mock.patch.object(self.runner, "enforce_tunnel_policy"):
            self.assertTrue(self.runner.hub_authorize(self.authorize_request(entry))["authorized"])
        self.assertEqual(self.files.read(helper.HUB_STATE, limit=helper.MAX_STATE), before)

    def test_last_available_authorization_slot_can_be_used(self):
        self.hub_state(helper.MAX_HUB_ENROLLMENTS - 1, helper.MAX_HUB_ACTIVE_ENROLLMENTS - 1)
        self.files.mkdir("/etc/ssh/sshd_config.d", 0o755)
        request = self.authorize_request()
        with mock.patch.object(self.runner, "effective", return_value={}), \
                mock.patch.object(self.runner, "hub_group"), mock.patch.object(self.runner, "account"), \
                mock.patch.object(self.runner, "owned_directory"), mock.patch.object(self.runner, "owned_write"), \
                mock.patch.object(self.runner, "enforce_tunnel_policy"):
            self.assertTrue(self.runner.hub_authorize(request)["authorized"])
        enrollments = self.runner.hub_state()["enrollments"]
        self.assertEqual(len(enrollments), helper.MAX_HUB_ENROLLMENTS)
        self.assertEqual(sum(not entry["revoked"] for entry in enrollments.values()), helper.MAX_HUB_ACTIVE_ENROLLMENTS)
        self.assertFalse(enrollments[request["enrollment_id"]]["revoked"])

    def test_state_uses_its_own_four_mib_limit_without_enlarging_other_reads(self):
        state = {"protocol": 1, "kind": "target", "fixture_padding": "x" * helper.MAX_RPC}
        self.runner.save_state("target", state)
        self.assertEqual(self.runner.load_state("target"), state)
        with self.assertRaises(helper.Refuse):
            self.runner.load_json(helper.TARGET_STATE)
        before = self.files.read(helper.TARGET_STATE, limit=helper.MAX_STATE)
        with self.assertRaises(helper.Refuse) as error:
            self.runner.save_state("target", dict(state, fixture_padding="x" * helper.MAX_STATE))
        self.assertEqual(error.exception.code, "STATE_CONFLICT")
        self.assertEqual(self.files.read(helper.TARGET_STATE, limit=helper.MAX_STATE), before)
        self.files.write(helper.TARGET_STATE, b" " * (helper.MAX_STATE + 1))
        with self.assertRaises(helper.Refuse):
            self.runner.load_state("target")
        oversized = helper.encode({"protocol": 1, "fixture_padding": "x" * helper.MAX_RPC})
        completed = subprocess.run([sys.executable, "-I", str(SOURCE), "hub-preview"],
                                   input=oversized, capture_output=True)
        self.assertEqual(json.loads(completed.stdout), {"protocol": 1, "ok": False, "error": "INVALID_REQUEST"})


class AccountRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.files=helper.Files(Path(self.temp.name),owner=os.getuid())
        self.commands=mock.Mock()
        self.commands.run.return_value=(0,b"")
        self.runner=helper.Enrollment(root=Path(self.temp.name),owner=os.getuid(),commands=self.commands)
        self.runner.check_cas=mock.Mock()
        self.runner.process_snapshot=mock.Mock(return_value={})
        self.identity={key:str(uuid.uuid4()) for key in ("request_id","enrollment_id","server_id")}

    def tearDown(self):self.temp.cleanup()

    def target_state(self,uid=None,gid=None):
        self.files.mkdir(helper.TARGET_STATE_DIR,0o700)
        state={"protocol":1,"kind":"target","identity":self.identity,"phase":"prepared",
               "source_files":{},"owned_files":{},"file_metadata":{},"owned_directories":{},"pending_writes":{},
               "agent_token_sha256":None,"ssh_public_key":None,"ssh_key_fingerprint":None,"local_port":None,"transport":None,
               "accounts":{"sovagrid":{"uid":uid,"gid":gid,"home":"/var/lib/sovagrid-agent",
                 "comment":"sovagrid-"+self.identity["enrollment_id"]+"-agent"}}}
        self.runner.save_state("target",state)
        return state

    def remove_target(self):
        return self.runner.target_remove({"protocol":1,**self.identity,"expected":dict.fromkeys(helper.CAS_FIELDS,"a"*64),"registration":None})

    def hub_state(self,uid=None):
        self.files.mkdir(helper.HUB_STATE_DIR,0o700)
        eid,sid=self.identity["enrollment_id"],self.identity["server_id"]
        name=helper.username(sid)
        record={"uid":uid,"gid":None if uid is None else 64200,"requested_uid":505 if uid is None else uid,"home":"/var/empty/"+name,
                "comment":"sovagrid-"+eid+"-hub-tunnel"}
        state={"protocol":1,"kind":"hub","group":{"name":helper.HUB_GROUP,"gid":64200},"owned_files":{},
               "file_metadata":{},"pending_writes":{},"owned_directories":{},"accounts":{name:record},
               "enrollments":{eid:{"enrollment_id":eid,"server_id":sid,"username":name,"ssh_public_key":ssh_key(),
                 "ssh_key_fingerprint":helper.public_key(ssh_key())[1],"revoked":False}}}
        self.runner.save_state("hub",state)
        return state,name

    def revoke_hub(self):
        return self.runner.hub_revoke({"protocol":1,"enrollment_id":self.identity["enrollment_id"],
             "server_id":self.identity["server_id"],"ssh_key_fingerprint":helper.public_key(ssh_key())[1],
             "expected":dict.fromkeys(helper.CAS_FIELDS,"a"*64)})

    def test_target_remove_clears_absent_uncreated_account_intent(self):
        self.target_state()
        with mock.patch.object(helper.pwd,"getpwnam",side_effect=KeyError),mock.patch.object(helper.grp,"getgrnam",side_effect=KeyError):
            self.assertTrue(self.remove_target()["removed"])
        self.runner.process_snapshot.assert_not_called()
        self.assertNotIn("sovagrid",self.runner.load_state("target")["accounts"])
        self.assertFalse(any(call.args[0][0] in ("/usr/sbin/userdel","/usr/sbin/groupdel") for call in self.commands.run.call_args_list))

    def test_target_groupdel_failure_and_lost_reply_keep_intent_for_retry(self):
        for failure_after_effect in (False,True):
            with self.subTest(failure_after_effect=failure_after_effect):
                self.target_state(uid=5005,gid=20005)
                exists=[True];attempts=[]
                def group(name):
                    if name=="sovagrid" and exists[0]:return SimpleNamespace(gr_name=name,gr_gid=20005,gr_mem=[])
                    raise KeyError(name)
                def command(argv,**options):
                    if argv[0]=="/usr/sbin/groupdel":
                        attempts.append(argv)
                        if len(attempts)==1:
                            if failure_after_effect:exists[0]=False
                            raise helper.Refuse("SERVICE_FAILED")
                        exists[0]=False
                    return 0,b""
                self.commands.run.side_effect=command
                with mock.patch.object(helper.pwd,"getpwnam",side_effect=KeyError),mock.patch.object(helper.grp,"getgrnam",side_effect=group):
                    with self.assertRaises(helper.Refuse):self.remove_target()
                    self.assertIn("sovagrid",self.runner.load_state("target")["accounts"])
                    self.assertTrue(self.remove_target()["removed"])
                    self.assertIsNone(self.runner.target_state(str(uuid.uuid4())))
                self.assertFalse(exists[0])
                self.assertEqual(len(attempts),1 if failure_after_effect else 2)

    def test_null_gid_orphan_group_is_preserved_and_reported(self):
        self.target_state()
        group=SimpleNamespace(gr_name="sovagrid",gr_gid=20005,gr_mem=[])
        with mock.patch.object(helper.pwd,"getpwnam",side_effect=KeyError),mock.patch.object(helper.grp,"getgrnam",return_value=group):
            with self.assertRaises(helper.Refuse) as error:self.remove_target()
        self.assertEqual(error.exception.code,"CLEANUP_REQUIRED")
        self.assertIn("sovagrid",self.runner.load_state("target")["accounts"])
        self.commands.run.assert_not_called()

    def test_hub_revoke_skips_signal_for_uncreated_or_already_deleted_account(self):
        for uid in (None,505):
            with self.subTest(uid=uid):
                _,name=self.hub_state(uid)
                with mock.patch.object(helper.pwd,"getpwnam",side_effect=KeyError),mock.patch.object(self.runner,"terminate_uid") as terminate:
                    self.assertTrue(self.revoke_hub()["revoked"])
                    self.assertTrue(self.revoke_hub()["revoked"])
                terminate.assert_not_called()
                self.assertNotIn(name,self.runner.hub_state()["accounts"])
                self.commands.run.assert_not_called()

    def test_hub_revoke_reconciles_lost_useradd_response_and_refuses_foreign_uid(self):
        state,name=self.hub_state()
        record=state["accounts"][name]
        entry=SimpleNamespace(pw_uid=505,pw_gid=64200,pw_gecos=record["comment"],pw_dir=record["home"],pw_shell="/usr/sbin/nologin")
        current=[entry]
        def user(_name):
            if current[0] is None:raise KeyError(_name)
            return current[0]
        group=SimpleNamespace(gr_name=helper.HUB_GROUP,gr_gid=64200,gr_mem=[])
        def command(argv,**options):
            self.assertEqual(argv,["/usr/sbin/userdel",name]);current[0]=None
            return 0,b""
        self.commands.run.side_effect=command
        with mock.patch.object(helper.pwd,"getpwnam",side_effect=user),mock.patch.object(helper.grp,"getgrnam",return_value=group),mock.patch.object(helper.os,"getgrouplist",return_value=[64200]),mock.patch.object(self.runner,"terminate_uid") as terminate:
            self.assertTrue(self.revoke_hub()["revoked"])
        self.assertEqual(terminate.call_args.args[1]["uid"],505)
        self.assertNotIn(name,self.runner.hub_state()["accounts"])
        state,name=self.hub_state(uid=505)
        current[0]=SimpleNamespace(**{**vars(entry),"pw_uid":506})
        with mock.patch.object(helper.pwd,"getpwnam",side_effect=user),mock.patch.object(helper.grp,"getgrnam",return_value=group),mock.patch.object(helper.os,"getgrouplist",return_value=[64200]),mock.patch.object(self.runner,"terminate_uid") as terminate:
            with self.assertRaises(helper.Refuse):self.revoke_hub()
        terminate.assert_not_called()

    def test_absent_name_with_live_numeric_uid_is_not_signalled_or_claimed_clean(self):
        self.hub_state(uid=505)
        self.runner.process_snapshot.return_value={123:(1,"S")}
        with mock.patch.object(helper.pwd,"getpwnam",side_effect=KeyError),mock.patch.object(self.runner,"terminate_uid") as terminate:
            with self.assertRaises(helper.Refuse) as error:self.revoke_hub()
        self.assertEqual(error.exception.code,"CLEANUP_REQUIRED")
        terminate.assert_not_called()

    def test_hub_creation_uses_durable_requested_uid_and_recovers_lost_useradd_reply(self):
        for lost_reply in (False, True):
            with self.subTest(lost_reply=lost_reply):
                state, name = self.hub_state()
                state["accounts"].clear()
                self.runner.save_state("hub", state)
                current = [None]
                def user(_name):
                    if current[0] is None: raise KeyError(_name)
                    return current[0]
                def uid(value):
                    if value == 999: return SimpleNamespace(pw_uid=999, pw_name="unrelated")
                    raise KeyError(value)
                calls = []
                def command(argv, **options):
                    calls.append(argv)
                    intent = self.runner.hub_state()["accounts"][name]
                    self.assertEqual((intent["uid"], intent["gid"], intent["requested_uid"]), (None, None, 998))
                    self.assertNotIn("--system", argv)
                    self.assertEqual(argv[argv.index("--uid") + 1], "998")
                    self.assertEqual(argv[argv.index("--expiredate") + 1], "1970-01-02")
                    self.assertEqual(argv[argv.index("--password") + 1], "*NP*")
                    current[0] = SimpleNamespace(pw_uid=998, pw_gid=64200, pw_gecos=intent["comment"],
                                                 pw_dir=intent["home"], pw_shell="/usr/sbin/nologin")
                    if lost_reply: raise helper.Refuse("SERVICE_FAILED")
                    return 0, b""
                self.commands.run.side_effect = command
                arguments = {"role":"hub-tunnel", "group_name":helper.HUB_GROUP,
                             "enrollment_id":self.identity["enrollment_id"]}
                with mock.patch.object(helper.pwd, "getpwnam", side_effect=user), \
                        mock.patch.object(helper.pwd, "getpwuid", side_effect=uid), \
                        mock.patch.object(helper.os, "getgrouplist", return_value=[64200]):
                    if lost_reply:
                        with self.assertRaises(helper.Refuse): self.runner.account("hub", state, name, **arguments)
                    self.runner.account("hub", self.runner.hub_state(), name, **arguments)
                self.assertEqual(len(calls), 1)
                saved = self.runner.hub_state()["accounts"][name]
                self.assertEqual((saved["uid"], saved["gid"], saved["requested_uid"]), (998, 64200, 998))

    def test_requested_uid_collision_never_reselects_or_signals_other_account(self):
        state, name = self.hub_state()
        before = self.files.read(helper.HUB_STATE)
        with mock.patch.object(helper.pwd, "getpwnam", side_effect=KeyError), \
                mock.patch.object(helper.pwd, "getpwuid", return_value=SimpleNamespace(pw_name="foreign", pw_uid=505)):
            for _ in range(2):
                with self.assertRaises(helper.Refuse) as error:
                    self.runner.account("hub", self.runner.hub_state(), name, role="hub-tunnel",
                                        group_name=helper.HUB_GROUP, enrollment_id=self.identity["enrollment_id"])
                self.assertEqual(error.exception.code, "OWNERSHIP_CONFLICT")
                self.assertEqual(self.files.read(helper.HUB_STATE), before)
        record = state["accounts"][name]
        wrong = SimpleNamespace(pw_uid=506, pw_gid=64200, pw_gecos=record["comment"],
                                pw_dir=record["home"], pw_shell="/usr/sbin/nologin")
        with mock.patch.object(helper.pwd, "getpwnam", return_value=wrong), \
                mock.patch.object(helper.os, "getgrouplist", return_value=[64200]), \
                mock.patch.object(self.runner, "terminate_uid") as terminate:
            with self.assertRaises(helper.Refuse): self.revoke_hub()
        terminate.assert_not_called()
        self.commands.run.assert_not_called()


class CommandTests(unittest.TestCase):
    def test_output_is_capped_during_read_and_timeout_kills_child(self):
        commands = helper.Commands()
        _, output = commands.run([sys.executable,"-I","-c","print('public fixture')"])
        self.assertEqual(output, b"public fixture\n")
        for script, limit, timeout in (("import os;os.write(1,b'x'*1000000)",128,2),
                                       ("import time;time.sleep(30)",128,0.2)):
            with self.subTest(script=script), self.assertRaises(helper.Refuse):
                commands.run([sys.executable,"-I","-c",script],limit=limit,timeout=timeout)


if __name__ == "__main__":
    unittest.main()
