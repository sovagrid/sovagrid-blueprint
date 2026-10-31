# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Bounded SSH RPC for the fixed, verified remote enrollment helper.

UI input is JSON stdin, never shell source. Stage capabilities are bound to this
RPC instance; restoring a journal descriptor first verifies remote ownership.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import tarfile
import tempfile
import threading
import time
import uuid

from .core import ConnectionOptions
from .installer import InstallError, ServerInstaller, _snapshot_with_digest
from .enrollment_protocol import (ACTIONS, FEATURE_ACTIONS, ERROR_MESSAGES, MAX_RPC, HelperError, ProtocolError,
    decode_reply, validate_request, validate_stage_descriptor)

LOCAL_ERRORS = {
    "INVALID_REPLY": "Не удалось подтвердить ответ установщика. Проверьте состояние перед повтором.",
    "SSH_FAILED": "SSH не подтвердил действие. Проверьте соединение и состояние установки.",
    "TIMEOUT": "Сервер не ответил вовремя. Проверьте состояние установки перед повтором.",
    "CANCELLED": "Действие отменено. Проверьте сохранённое состояние установки.",
    "BUSY": "Дождитесь завершения текущего действия установки.",
    "STAGE_NOT_FOUND": "Временный пакет на сервере уже удалён. Подготовьте его заново.",
    "STAGE_INCOMPLETE": "Передача временного пакета не завершена. Подготовьте его заново.",
    "STAGE_BUSY": "Временный пакет используется другим действием. Дождитесь его завершения.",
}


class RPCError(RuntimeError):
    def __init__(self, code, *, stage=None):
        self.code = code if code in ERROR_MESSAGES or code in LOCAL_ERRORS else "INVALID_REPLY"
        self.stage = stage
        super().__init__((ERROR_MESSAGES | LOCAL_ERRORS)[self.code])


@dataclass(frozen=True)
class Stage:
    remote_dir: str
    sha256: str
    source_manifest_sha256: str
    helper_sha256: str
    stage_id: str
    _owner: object = field(default=None, repr=False, compare=False)
    _cleanup_only: bool = field(default=False, repr=False, compare=False)

    def descriptor(self):
        return validate_stage_descriptor({key: getattr(self, key) for key in
            ("remote_dir", "sha256", "source_manifest_sha256", "helper_sha256", "stage_id")})


class _WindowsJob:
    """Keep descendants killable even after the SSH parent has exited.

    https://learn.microsoft.com/windows/win32/procthread/job-objects
    The trusted OpenSSH executable is assigned immediately on creation; this
    is lifecycle cleanup, not a sandbox for adversarial local executables.
    """
    def __init__(self):
        import ctypes
        from ctypes import wintypes
        class Basic(ctypes.Structure):
            _fields_ = [("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong),
                ("flags", wintypes.DWORD), ("min_working", ctypes.c_size_t), ("max_working", ctypes.c_size_t),
                ("active", wintypes.DWORD), ("affinity", ctypes.c_size_t),
                ("priority", wintypes.DWORD), ("scheduling", wintypes.DWORD)]
        class Counters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in
                ("reads", "writes", "other", "read_bytes", "write_bytes", "other_bytes")]
        class Extended(ctypes.Structure):
            _fields_ = [("basic", Basic), ("io", Counters), ("process_memory", ctypes.c_size_t),
                ("job_memory", ctypes.c_size_t), ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]
        self._api = ctypes.WinDLL("kernel32", use_last_error=True)
        self._api.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self._api.CreateJobObjectW.restype = wintypes.HANDLE
        self._api.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        self._api.SetInformationJobObject.restype = wintypes.BOOL
        self._api.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self._api.AssignProcessToJobObject.restype = wintypes.BOOL
        self._api.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self._api.TerminateJobObject.restype = wintypes.BOOL
        self._api.CloseHandle.argtypes = [wintypes.HANDLE]
        self._api.CloseHandle.restype = wintypes.BOOL
        self._handle = self._api.CreateJobObjectW(None, None)
        if not self._handle:
            raise OSError("Cannot create SSH lifecycle job")
        limits = Extended(); limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self._api.SetInformationJobObject(self._handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.close(); raise OSError("Cannot restrict SSH lifecycle job")

    def assign(self, process):
        if not self._api.AssignProcessToJobObject(self._handle, int(process._handle)):
            raise OSError("Cannot assign SSH lifecycle job")

    def terminate(self):
        if self._handle:
            self._api.TerminateJobObject(self._handle, 1)

    def close(self):
        if self._handle:
            self._api.CloseHandle(self._handle)
            self._handle = None


# This source is carried by the trusted Connect executable, not read from the
# remote source tree. It runs before any bundled helper code is executed.
_REMOTE_COMMON = r'''
import base64, fcntl, hashlib, io, json, os, pathlib, re, shutil, stat, sys, tarfile
MAX=32768
SELF='sovagrid-blueprint/deploy/remote_agent.py'
TARGET='/opt/sovagrid-agent-installer/remote_agent.py'
COMPONENTS={'sovagrid-blueprint','sovagrid-agent','sovagrid-hub','sovagrid-web','sovagrid-vpn'}
SHA=re.compile(r'[0-9a-f]{64}\Z')
class Stop(Exception):
    def __init__(self,code): self.code=code
def need(condition,code='SOURCE_UNTRUSTED'):
    if not condition: raise Stop(code)
def pairs(items):
    value={}
    for key,item in items:
        need(key not in value,'INVALID_REQUEST'); value[key]=item
    return value
def parse(raw):
    try: return json.loads(raw,object_pairs_hook=pairs)
    except (ValueError,UnicodeError,TypeError,RecursionError): raise Stop('INVALID_REQUEST') from None
def emit(value): sys.stdout.buffer.write(json.dumps(value,separators=(',',':')).encode()+b'\n'); sys.stdout.buffer.flush()
def failure(code): emit({'protocol':1,'ok':False,'error':code})
def exact(value,fields): need(isinstance(value,dict) and set(value)==set(fields),'INVALID_REQUEST')
def root(): need(os.geteuid()==0,'ROOT_REQUIRED')
def inspect(path,directory=False,private=False):
    path=pathlib.Path(path)
    need(path.is_absolute() and '..' not in path.parts)
    for parent in reversed(path.parents):
        item=os.lstat(parent)
        sticky=str(parent)=='/var/tmp' and stat.S_IMODE(item.st_mode)==0o1777
        need(stat.S_ISDIR(item.st_mode) and item.st_uid==0 and (not item.st_mode&0o022 or sticky))
    item=os.lstat(path)
    need(item.st_uid==0 and not item.st_mode&0o022)
    need(stat.S_ISDIR(item.st_mode) if directory else stat.S_ISREG(item.st_mode) and item.st_nlink==1)
    if private: need(stat.S_IMODE(item.st_mode)==(0o700 if directory else 0o600))
    return item
def read(path,limit,private=False):
    inspect(path,private=private)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        item=os.fstat(fd); need(stat.S_ISREG(item.st_mode) and item.st_nlink==1 and item.st_uid==0 and not item.st_mode&0o022)
        need(item.st_size<=limit)
        data=bytearray()
        while len(data)<=limit:
            chunk=os.read(fd,min(131072,limit-len(data)+1))
            if not chunk: break
            data.extend(chunk)
        need(len(data)<=limit)
        return bytes(data)
    finally: os.close(fd)
def file_hash(path,limit):
    inspect(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        item=os.fstat(fd); need(item.st_uid==0 and stat.S_ISREG(item.st_mode) and item.st_nlink==1 and not item.st_mode&0o022 and item.st_size<=limit)
        total=0; result=hashlib.sha256()
        while True:
            chunk=os.read(fd,131072)
            if not chunk: break
            total+=len(chunk); need(total<=limit); result.update(chunk)
        return result.hexdigest(),total
    finally: os.close(fd)
def safe_name(name):
    need(isinstance(name,str) and 1<=len(name)<=240 and name.isascii() and '\\' not in name)
    parts=name.split('/')
    need(all(part not in ('','.','..') and re.fullmatch(r'[A-Za-z0-9_.@-]+',part) for part in parts))
    need(name=='sovagrid-bundle.json' or parts[0] in COMPONENTS)
    return name
def manifest(raw):
    value=parse(raw); exact(value,{'format','components','sha256'})
    need(type(value['format']) is int and value['format']==1 and isinstance(value['components'],dict) and set(value['components'])==COMPONENTS)
    need(isinstance(value['sha256'],dict) and 1<=len(value['sha256'])<=4096 and SELF in value['sha256'])
    for name,sha in value['sha256'].items(): safe_name(name); need(isinstance(sha,str) and SHA.fullmatch(sha))
    for name,record in value['components'].items():
        exact(record,{'commit','file_count'})
        need(isinstance(record['commit'],str) and re.fullmatch(r'[0-9a-f]{40}',record['commit']))
        need(type(record['file_count']) is int and record['file_count']>0 and record['file_count']==sum(n.startswith(name+'/') for n in value['sha256']))
    return value
def source(path,expected_manifest=None,expected_helper=None,caller_manifest=None):
    inspect(path,directory=True)
    raw=read(path+'/sovagrid-bundle.json',524288)
    need(expected_manifest is None or hashlib.sha256(raw).hexdigest()==expected_manifest,'SOURCE_CHANGED')
    need(caller_manifest is None or hashlib.sha256(raw).hexdigest()==caller_manifest,'STALE_PREVIEW')
    value=manifest(raw); actual=set(); expanded=0; entries=0
    for directory,dirs,files in os.walk(path,followlinks=False):
        inspect(directory,directory=True)
        for name in dirs: inspect(directory+'/'+name,directory=True)
        for name in files:
            absolute=directory+'/'+name; relative=pathlib.Path(absolute).relative_to(path).as_posix(); safe_name(relative)
            entries+=1; need(entries<=4097)
            if relative=='sovagrid-bundle.json': continue
            need(relative in value['sha256'])
            sha,size=file_hash(absolute,33554432); expanded+=size; need(expanded<=268435456)
            need(sha==value['sha256'][relative],'SOURCE_CHANGED'); actual.add(relative)
    need(actual==set(value['sha256']))
    code=read(path+'/'+SELF,1048576)
    need(b'SOVAGRID_REMOTE_AGENT_HELPER_V1' in code)
    need(expected_helper is None or hashlib.sha256(code).hexdigest()==expected_helper,'SOURCE_CHANGED')
    return code
def descriptor(value):
    exact(value,{'remote_dir','sha256','source_manifest_sha256','helper_sha256','stage_id'})
    need(isinstance(value['stage_id'],str) and re.fullmatch(r'[0-9a-f]{32}',value['stage_id']),'INVALID_REQUEST')
    need(value['remote_dir']=='/var/tmp/sovagrid-agent-enroll.'+value['stage_id'],'INVALID_REQUEST')
    need(all(isinstance(value[key],str) and SHA.fullmatch(value[key]) for key in ('sha256','source_manifest_sha256','helper_sha256')),'INVALID_REQUEST')
    return value
def stage_info(value,complete=True):
    value=descriptor(value); path=value['remote_dir']
    if not os.path.lexists(path): raise Stop('STAGE_NOT_FOUND')
    inspect(path,directory=True,private=True)
    marker=parse(read(path+'/stage.json',4096,private=True)); exact(marker,{'protocol','stage','complete'})
    need(type(marker['protocol']) is int and marker['protocol']==1 and marker['stage']==value and type(marker['complete']) is bool)
    if complete: need(marker['complete'],'STAGE_INCOMPLETE')
    return marker
def stage_lock(value):
    path=value['remote_dir']+'/rpc.lock'; inspect(path,private=True)
    fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW)
    try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError: os.close(fd); raise Stop('STAGE_BUSY')
    return fd
def checked_stage(value):
    stage_info(value)
    need(file_hash(value['remote_dir']+'/bundle.tar.gz',67108864)[0]==value['sha256'],'SOURCE_CHANGED')
    return source(value['remote_dir']+'/source',value['source_manifest_sha256'],value['helper_sha256'])
def installed_target(caller_manifest=None):
    state=parse(read('/var/lib/sovagrid-agent-enrollment/state.json',4194304,private=True))
    need(isinstance(state,dict) and state.get('kind')=='target' and isinstance(state.get('source_files'),dict))
    raw=read('/opt/sovagrid-agent-installer/source-manifest.json',524288)
    need(hashlib.sha256(raw).hexdigest()==state.get('source_manifest_sha256'),'SOURCE_CHANGED')
    need(caller_manifest is None or hashlib.sha256(raw).hexdigest()==caller_manifest,'STALE_PREVIEW')
    value=manifest(raw); expected={TARGET:value['sha256'][SELF]}
    legal={'LICENSE','NOTICE','ATTRIBUTION.md','README.md','THIRD_PARTY_NOTICES.txt','deploy/sovagrid-agent.service'}
    for name,sha in value['sha256'].items():
        if not name.startswith('sovagrid-agent/'): continue
        relative=name[len('sovagrid-agent/'):]
        if relative in legal or relative.startswith('sovagrid_agent/') and relative.endswith('.py') and '__pycache__' not in relative.split('/'):
            expected['/opt/sovagrid-agent/'+relative]=sha
    need({'/opt/sovagrid-agent/sovagrid_agent/__main__.py','/opt/sovagrid-agent/LICENSE','/opt/sovagrid-agent/NOTICE','/opt/sovagrid-agent/ATTRIBUTION.md','/opt/sovagrid-agent/deploy/sovagrid-agent.service'}<=set(expected))
    need(state['source_files']==expected,'SOURCE_CHANGED')
    for path,sha in expected.items(): need(file_hash(path,33554432)[0]==sha,'SOURCE_CHANGED')
    code=read(TARGET,1048576); need(b'SOVAGRID_REMOTE_AGENT_HELPER_V1' in code)
    return code
'''

_PREFLIGHT = r'''
import json,os,platform,subprocess,sys
try:
    if sys.version_info<(3,10): raise ValueError('platform')
    values={}
    with open('/usr/lib/os-release',encoding='utf-8') as stream:
        for line in stream:
            key,sep,value=line.strip().partition('=')
            if sep: values[key]=value.strip('"')
    if values.get('ID')!='ubuntu' or values.get('VERSION_ID') not in ('22.04','24.04','26.04'): raise ValueError('platform')
    if not os.path.isdir('/run/systemd/system'): raise ValueError('systemd')
    child=subprocess.Popen(['/usr/bin/systemctl','--version'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    try: data=child.stdout.read(256)
    finally:
        if child.poll() is None: child.kill()
        child.wait(timeout=5); child.stdout.close()
    version=data.decode('ascii').splitlines()[0].split()[1]
    if int(version.split('.')[0])<247: raise ValueError('systemd')
    result={'protocol':1,'ok':True,'euid':os.geteuid(),'ubuntu_version':values['VERSION_ID'],'python_version':platform.python_version(),'systemd_version':version}
except ValueError as error:
    result={'protocol':1,'ok':False,'error':'UNSUPPORTED_SYSTEMD' if str(error)=='systemd' else 'UNSUPPORTED_PLATFORM'}
except Exception:
    result={'protocol':1,'ok':False,'error':'UNSUPPORTED_PLATFORM'}
sys.stdout.write(json.dumps(result,separators=(',',':'))+'\n')
sys.exit(0 if result['ok'] else 1)
'''

_CALL_SCRIPT = _REMOTE_COMMON + r'''
try:
    root(); raw=sys.stdin.buffer.read(MAX+1); need(len(raw)<=MAX,'INVALID_REQUEST')
    envelope=parse(raw); exact(envelope,{'role','action','stage','payload'})
    role,action=envelope['role'],envelope['action']
    choices={'target-preview','target-prepare','target-transport','target-registered','target-activate','target-status','target-remove','hub-preview','hub-authorize','hub-status','hub-revoke','target-features-status','target-features-preview','target-features-apply'}
    need(role in ('hub','target') and action in choices and action.startswith(role+'-'),'INVALID_REQUEST')
    need(not action.startswith('target-features-') or envelope['stage'] is not None,'INVALID_REQUEST')
    payload=envelope['payload']; need(isinstance(payload,dict),'INVALID_REQUEST')
    encoded=json.dumps(payload,separators=(',',':'),ensure_ascii=False).encode(); need(len(encoded)<=MAX,'INVALID_REQUEST')
    requested=payload.get('expected'); caller_manifest=None
    if requested is not None:
        exact(requested,{'source_manifest_sha256','features_sha256','policy_sha256','state_sha256'})
        need(all(isinstance(item,str) and SHA.fullmatch(item) for item in requested.values()),'INVALID_REQUEST')
        caller_manifest=requested['source_manifest_sha256']
    lock_fd=None
    if role=='hub':
        need(envelope['stage'] is None,'INVALID_REQUEST')
        read('/var/lib/sovagrid/.managed-by-run-sh',1024,private=True)
        path='/opt/sovagrid-src/'+SELF; code=source('/opt/sovagrid-src',caller_manifest=caller_manifest)
    elif envelope['stage'] is not None:
        value=descriptor(envelope['stage']); stage_info(value); lock_fd=stage_lock(value)
        need(caller_manifest is None or caller_manifest==value['source_manifest_sha256'],'STALE_PREVIEW')
        code=checked_stage(value)
        path=value['remote_dir']+'/source/'+SELF
    else:
        path=TARGET; code=installed_target(caller_manifest)
    sys.argv=[path,action]; sys.stdin=io.TextIOWrapper(io.BytesIO(encoded),encoding='utf-8')
    exec(compile(code,path,'exec'),{'__name__':'__main__','__file__':path})
except Stop as error: failure(error.code); sys.exit(1)
except Exception: failure('SOURCE_UNTRUSTED'); sys.exit(1)
'''

_STAGE_SCRIPT = _REMOTE_COMMON + r'''
created=False; value=None
def marker(complete):
    path=value['remote_dir']+'/stage.json'
    data=json.dumps({'protocol':1,'stage':value,'complete':complete},separators=(',',':')).encode()
    temporary=path+'.new'; fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream: stream.write(data); stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary,path)
def cleanup():
    if created:
        stage_info(value,False)
        need(shutil.rmtree.avoids_symlink_attacks)
        shutil.rmtree(value['remote_dir'])
try:
    root(); os.umask(0o077); header=sys.stdin.buffer.readline(4097); need(len(header)<=4096 and header.endswith(b'\n'),'INVALID_REQUEST')
    header=parse(header); exact(header,{'protocol','stage','archive_size'})
    need(type(header['protocol']) is int and header['protocol']==1,'INVALID_REQUEST')
    value=descriptor(header['stage']); size=header['archive_size']
    need(type(size) is int and 0<size<=67108864,'INVALID_REQUEST')
    inspect('/var',directory=True)
    tmp=os.lstat('/var/tmp'); need(stat.S_ISDIR(tmp.st_mode) and tmp.st_uid==0 and stat.S_IMODE(tmp.st_mode)==0o1777)
    os.mkdir(value['remote_dir'],0o700); created=True
    lock_fd=os.open(value['remote_dir']+'/rpc.lock',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    fcntl.flock(lock_fd,fcntl.LOCK_EX|fcntl.LOCK_NB); marker(False)
    fd=os.open(value['remote_dir']+'/bundle.tar.gz',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    digest=hashlib.sha256(); remaining=size
    with os.fdopen(fd,'wb') as output:
        while remaining:
            chunk=sys.stdin.buffer.read(min(131072,remaining)); need(chunk,'SOURCE_UNTRUSTED')
            output.write(chunk); digest.update(chunk); remaining-=len(chunk)
        need(not sys.stdin.buffer.read(1),'SOURCE_UNTRUSTED'); output.flush(); os.fsync(output.fileno())
    need(digest.hexdigest()==value['sha256'],'SOURCE_CHANGED')
    base=value['remote_dir']+'/source'; os.mkdir(base,0o755); seen=set(); expanded=0
    with tarfile.open(value['remote_dir']+'/bundle.tar.gz','r:gz') as archive:
        need(not archive.pax_headers)
        for item in archive:
            name=safe_name(item.name.rstrip('/') if item.isdir() else item.name)
            need(name not in seen and len(seen)<8192 and not item.pax_headers); seen.add(name)
            need(item.mode in ((0o755,) if item.isdir() else (0o644,0o755)))
            absolute=base+'/'+name
            if item.isdir():
                os.makedirs(absolute,mode=0o755,exist_ok=True); inspect(absolute,directory=True); continue
            need(item.isfile() and 0<=item.size<=33554432); expanded+=item.size; need(expanded<=268435456)
            os.makedirs(str(pathlib.Path(absolute).parent),mode=0o755,exist_ok=True)
            fd=os.open(absolute,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,item.mode)
            with os.fdopen(fd,'wb') as output:
                stream=archive.extractfile(item); need(stream is not None); remaining=item.size
                while remaining:
                    chunk=stream.read(min(131072,remaining)); need(chunk); output.write(chunk); remaining-=len(chunk)
                output.flush(); os.fsync(output.fileno())
    source(base,value['source_manifest_sha256'],value['helper_sha256']); marker(True)
    emit({'protocol':1,'ok':True,'stage':value})
except Stop as error:
    try: cleanup()
    except Exception: failure('CLEANUP_REQUIRED'); sys.exit(1)
    failure(error.code); sys.exit(1)
except Exception:
    try: cleanup()
    except Exception: failure('CLEANUP_REQUIRED'); sys.exit(1)
    failure('SOURCE_UNTRUSTED'); sys.exit(1)
'''

_STAGE_CONTROL = _REMOTE_COMMON + r'''
try:
    root(); raw=sys.stdin.buffer.read(MAX+1); need(len(raw)<=MAX,'INVALID_REQUEST')
    value=parse(raw); exact(value,{'stage','action'}); operation=value['action']; value=descriptor(value['stage'])
    need(operation in ('recover','recover_cleanup','cleanup'),'INVALID_REQUEST')
    if operation=='cleanup' and not os.path.lexists(value['remote_dir']):
        emit({'protocol':1,'ok':True,'cleaned':True}); sys.exit(0)
    info=stage_info(value,operation=='recover'); lock_fd=stage_lock(value)
    info=stage_info(value,operation=='recover')
    if info['complete']: checked_stage(value)
    if operation!='recover':
        # Even partial uploads may contain only regular owned scratch files.
        count=0
        for directory,dirs,files in os.walk(value['remote_dir'],followlinks=False):
            inspect(directory,directory=True)
            for name in dirs: inspect(directory+'/'+name,directory=True)
            for name in files: inspect(directory+'/'+name); count+=1; need(count<=8197)
    if operation in ('recover','recover_cleanup'): emit({'protocol':1,'ok':True,'stage':value})
    else:
        need(shutil.rmtree.avoids_symlink_attacks); shutil.rmtree(value['remote_dir'])
        emit({'protocol':1,'ok':True,'cleaned':True})
except Stop as error: failure(error.code); sys.exit(1)
except SystemExit: raise
except Exception: failure('SOURCE_UNTRUSTED'); sys.exit(1)
'''


class AgentRPC:
    def __init__(self, options: ConnectionOptions, *, role, progress=None, popen=subprocess.Popen):
        if role not in ("hub", "target"):
            raise ValueError("role must be hub or target")
        self.options = options.validated()
        self.role = role
        self._progress = progress or (lambda _message: None)
        self._popen = popen
        self._lock = threading.Lock()
        self._operation_lock = threading.RLock()
        self._cancelled = threading.Event()
        self._process = None
        self._prefix = None
        self._owner = object()
        self._stages = {}
        self._installer = ServerInstaller(self.options, popen=self._spawn)
        self._timeouts = {"preflight": 30, "stage": 180, "cleanup": 30,
            **{action: 30 for action in ACTIONS}, "target-prepare": 120, "target-transport": 60,
            "target-registered": 60, "target-activate": 60, "target-remove": 120, "hub-revoke": 120,
            "target-features-apply": 180}

    def _spawn(self, argv, **kwargs):
        job = None
        if os.name == "posix":
            kwargs["start_new_session"] = True
        elif os.name == "nt":
            kwargs["creationflags"] = kwargs.get("creationflags", 0) | subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
            job = _WindowsJob()
        process = None
        try:
            process = self._popen(argv, **kwargs)
            if job is not None:
                job.assign(process)
                process._sovagrid_rpc_job = job
            return process
        except Exception:
            if process is not None and process.poll() is None:
                process.kill(); process.wait(timeout=5)
            if process is not None:
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None: stream.close()
            if job is not None: job.close()
            raise

    @contextmanager
    def _operation(self):
        if not self._operation_lock.acquire(blocking=False):
            raise RPCError("BUSY")
        try:
            self._check_cancelled()
            yield
        finally:
            self._operation_lock.release()

    def _check_cancelled(self):
        if self._cancelled.is_set():
            raise RPCError("CANCELLED")

    def cancel(self):
        # The worker owns process-tree termination and pipe/thread reaping.
        # This method is safe to call directly from a GUI event handler.
        self._cancelled.set()

    @staticmethod
    def _kill(process):
        if os.name == "posix":
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
        elif os.name == "nt":
            job = getattr(process, "_sovagrid_rpc_job", None)
            if job is not None: job.terminate()
        if process.poll() is None:
            process.kill()

    def _exchange(self, script, chunks, timeout, *, prefix=None):
        self._check_cancelled()
        command = (self._prefix if prefix is None else prefix) + "/usr/bin/python3 -I -c " + shlex.quote(script)
        with self._installer._session() as (config, helper):
            try:
                process = self._installer._ssh(config, helper, command, input_file=subprocess.PIPE)
            except (OSError, InstallError):
                raise RPCError("SSH_FAILED") from None
            with self._lock:
                self._process = process
            output = bytearray(); overflow = threading.Event(); errors = []
            def read():
                try:
                    while True:
                        part = process.stdout.read(min(4096, MAX_RPC - len(output) + 1))
                        if not part: return
                        output.extend(part)
                        if len(output) > MAX_RPC: overflow.set(); return
                except (OSError, ValueError): errors.append("read")
            def write():
                try:
                    for part in chunks:
                        self._check_cancelled()
                        view = memoryview(part)
                        while view:
                            count = process.stdin.write(view)
                            if not count: raise OSError
                            view = view[count:]
                    process.stdin.flush()
                except (OSError, ValueError, RPCError): errors.append("write")
                finally:
                    try: process.stdin.close()
                    except (OSError, ValueError): pass
            reader = threading.Thread(target=read, daemon=True, name="sovagrid-rpc-reader")
            writer = threading.Thread(target=write, daemon=True, name="sovagrid-rpc-writer")
            reader.start(); writer.start()
            deadline = time.monotonic() + timeout; failure = None
            try:
                while process.poll() is None or reader.is_alive() or writer.is_alive():
                    if self._cancelled.is_set(): failure = "CANCELLED"; break
                    if overflow.is_set(): failure = "INVALID_REPLY"; break
                    if time.monotonic() >= deadline: failure = "TIMEOUT"; break
                    self._cancelled.wait(0.02)
                if failure:
                    self._kill(process)
                process.wait(timeout=5)
                reader.join(5); writer.join(5)
                if reader.is_alive() or writer.is_alive():
                    raise RPCError("CLEANUP_REQUIRED")
                if failure: raise RPCError(failure)
                self._check_cancelled()
                if overflow.is_set() or errors and process.returncode == 0:
                    raise RPCError("INVALID_REPLY")
                return bytes(output), process.returncode
            except (OSError, subprocess.TimeoutExpired):
                raise RPCError("SSH_FAILED") from None
            finally:
                if process.poll() is None:
                    self._kill(process)
                    try: process.wait(timeout=5)
                    except subprocess.TimeoutExpired: pass
                for stream in (process.stdout, process.stdin):
                    try: stream.close()
                    except (OSError, ValueError): pass
                reader.join(5); writer.join(5)
                with self._lock:
                    if self._process is process: self._process = None
                with self._installer._lock:
                    if self._installer._process is process: self._installer._process = None
                job = getattr(process, "_sovagrid_rpc_job", None)
                if job is not None: job.close()

    @staticmethod
    def _json(value):
        try:
            raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise RPCError("INVALID_REQUEST") from None
        if len(raw) > MAX_RPC:
            raise RPCError("INVALID_REQUEST")
        return raw

    @staticmethod
    def _public(raw, code):
        try:
            def pairs(items):
                result = {}
                for key, value in items:
                    if key in result: raise ProtocolError()
                    result[key] = value
                return result
            if not raw or len(raw) > MAX_RPC: raise ProtocolError()
            value = json.loads(raw, object_pairs_hook=pairs)
            if not isinstance(value, dict) or type(value.get("protocol")) is not int or value["protocol"] != 1 or type(value.get("ok")) is not bool:
                raise ProtocolError()
            if value["ok"] is False:
                if set(value) != {"protocol", "ok", "error"} or not isinstance(value["error"], str) or value["error"] not in ERROR_MESSAGES | LOCAL_ERRORS:
                    raise ProtocolError()
                raise RPCError(value["error"])
            if code != 0: raise RPCError("SSH_FAILED")
            return value
        except (ValueError, UnicodeError, RecursionError):
            raise RPCError("INVALID_REPLY") from None

    def preflight(self):
        with self._operation():
            self._progress("Проверка Ubuntu, Python и прав установки по SSH…")
            def probe(prefix):
                raw, code = self._exchange(_PREFLIGHT, (), self._timeouts["preflight"], prefix=prefix)
                value = self._public(raw, code)
                expected = {"protocol", "ok", "euid", "ubuntu_version", "python_version", "systemd_version"}
                if set(value) != expected or type(value["euid"]) is not int or not 0 <= value["euid"] <= 2**31 - 1:
                    raise RPCError("INVALID_REPLY")
                if any(not isinstance(value[key], str) or not 1 <= len(value[key]) <= 64 or not value[key].isprintable() for key in
                       ("ubuntu_version", "python_version", "systemd_version")):
                    raise RPCError("INVALID_REPLY")
                if value["ubuntu_version"] not in ("22.04", "24.04", "26.04"):
                    raise RPCError("UNSUPPORTED_PLATFORM")
                return value
            value = probe("")
            prefix = ""
            if value["euid"] != 0:
                try: value = probe("sudo -n -- ")
                except RPCError as error:
                    if error.code in ("SSH_FAILED", "INVALID_REPLY"): raise RPCError("ROOT_REQUIRED") from None
                    raise
                prefix = "sudo -n -- "
            if value["euid"] != 0: raise RPCError("ROOT_REQUIRED")
            self._check_cancelled()
            self._prefix = prefix
            return value

    def _ready(self):
        if self._prefix is None:
            self.preflight()

    def _owned(self, stage):
        if not isinstance(stage, Stage) or stage._owner is not self._owner or self._stages.get(stage.stage_id) is not stage:
            raise RPCError("OWNERSHIP_CONFLICT")
        try: stage.descriptor()
        except ProtocolError: raise RPCError("OWNERSHIP_CONFLICT") from None
        return stage

    def call(self, action, payload, stage=None):
        with self._operation():
            if not isinstance(action, str) or action not in ACTIONS or not action.startswith(self.role + "-") or stage is not None and self.role != "target":
                raise RPCError("INVALID_REQUEST")
            if action in FEATURE_ACTIONS and stage is None:
                raise RPCError("INVALID_REQUEST")
            try: clean = validate_request(action, payload)
            except (ProtocolError, TypeError): raise RPCError("INVALID_REQUEST") from None
            if stage is not None:
                self._owned(stage)
                if stage._cleanup_only: raise RPCError("STAGE_INCOMPLETE")
            self._ready()
            envelope = {"role": self.role, "action": action, "stage": stage.descriptor() if stage else None, "payload": clean}
            raw, code = self._exchange(_CALL_SCRIPT, (self._json(envelope),), self._timeouts[action])
            self._public(raw, code)
            try:
                result = decode_reply(action, raw, request=clean)
                self._check_cancelled()
                return result
            except HelperError as error: raise RPCError(error.code) from None
            except ProtocolError: raise RPCError("INVALID_REPLY") from None

    def stage_target(self, bundle, sha256, *, checkpoint=None):
        """Checkpoint receives a public descriptor before any remote creation."""
        with self._operation():
            if self.role != "target": raise RPCError("INVALID_REQUEST")
            if not isinstance(sha256, str) or re.fullmatch(r"[0-9a-f]{64}", sha256) is None:
                raise RPCError("INVALID_REQUEST")
            with tempfile.TemporaryDirectory(prefix="sovagrid-agent-rpc-") as temporary:
                snapshot = Path(temporary) / "bundle.tar.gz"
                try:
                    summary, actual = _snapshot_with_digest(Path(bundle), snapshot, sha256)
                    with tarfile.open(snapshot, "r:gz") as archive:
                        manifest = archive.extractfile("sovagrid-bundle.json").read(524289)
                        helper = archive.extractfile("sovagrid-blueprint/deploy/remote_agent.py")
                        if helper is None: raise RPCError("SOURCE_UNTRUSTED")
                        code = helper.read(1048577)
                    if len(manifest) > 524288 or len(code) > 1048576 or b"SOVAGRID_REMOTE_AGENT_HELPER_V1" not in code:
                        raise RPCError("SOURCE_UNTRUSTED")
                except (OSError, InstallError, tarfile.TarError, KeyError):
                    raise RPCError("SOURCE_UNTRUSTED") from None
                identifier = uuid.uuid4().hex
                stage = Stage("/var/tmp/sovagrid-agent-enroll." + identifier, actual,
                    hashlib.sha256(manifest).hexdigest(), hashlib.sha256(code).hexdigest(), identifier, self._owner)
                self._stages[identifier] = stage
                if checkpoint is not None: checkpoint(stage.descriptor())
                self._ready()
                header = self._json({"protocol": 1, "stage": stage.descriptor(), "archive_size": summary.size}) + b"\n"
                def chunks():
                    yield header
                    with snapshot.open("rb") as stream:
                        for part in iter(lambda: stream.read(131072), b""): yield part
                try:
                    raw, status = self._exchange(_STAGE_SCRIPT, chunks(), self._timeouts["stage"])
                    value = self._public(raw, status)
                    if set(value) != {"protocol", "ok", "stage"} or validate_stage_descriptor(value["stage"]) != stage.descriptor():
                        raise RPCError("INVALID_REPLY")
                    self._check_cancelled()
                    return stage
                except ProtocolError:
                    raise RPCError("INVALID_REPLY", stage=stage) from None
                except RPCError as error:
                    error.stage = stage
                    raise

    def recover_stage(self, descriptor, *, for_cleanup=False):
        with self._operation():
            if self.role != "target": raise RPCError("INVALID_REQUEST")
            try: clean = validate_stage_descriptor(descriptor)
            except ProtocolError: raise RPCError("OWNERSHIP_CONFLICT") from None
            self._ready()
            if type(for_cleanup) is not bool: raise RPCError("INVALID_REQUEST")
            raw, status = self._exchange(_STAGE_CONTROL, (self._json({"action": "recover_cleanup" if for_cleanup else "recover", "stage": clean}),), self._timeouts["cleanup"])
            result = self._public(raw, status)
            if set(result) != {"protocol", "ok", "stage"} or result["stage"] != clean:
                raise RPCError("INVALID_REPLY")
            self._check_cancelled()
            stage = Stage(**clean, _owner=self._owner, _cleanup_only=for_cleanup)
            self._stages[stage.stage_id] = stage
            return stage

    def cleanup_stage(self, stage):
        with self._operation():
            self._owned(stage)
            if self.role != "target": raise RPCError("INVALID_REQUEST")
            self._ready()
            raw, status = self._exchange(_STAGE_CONTROL, (self._json({"action": "cleanup", "stage": stage.descriptor()}),), self._timeouts["cleanup"])
            result = self._public(raw, status)
            if result != {"protocol": 1, "ok": True, "cleaned": True}:
                raise RPCError("INVALID_REPLY")
            self._check_cancelled()
            self._stages.pop(stage.stage_id, None)
