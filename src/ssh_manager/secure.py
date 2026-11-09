"""Staged onboarding using native OpenSSH and a server-side recovery timer."""
from __future__ import annotations
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import secrets
import shlex
import socket
import subprocess
import sys
import tempfile
import threading
import time
import math

RECONNECT_WINDOW_SECONDS = 30
from .secure_remote import REMOTE_SCRIPT


def generate_account_password():
    alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789'
    return '-'.join(''.join(secrets.choice(alphabet) for _ in range(6)) for _ in range(2))

# The unprivileged wrapper captures the actual login and SSH connection before
# sudo filters the environment. Credential data is sent only through SSH stdin.
WRAPPER = r'''
import json,os,pwd,subprocess,sys
p=json.load(sys.stdin)
p['_actual_user']=pwd.getpwuid(os.getuid()).pw_name
p['_connection']=os.environ.get('SSH_CONNECTION','')
script=p.pop('_script')
secret=p.pop('_sudo_password','')
expect_password=p.pop('_expect_password',False)
if os.geteuid()==0:cmd=[sys.executable,'-c',script]
else:
    if expect_password and subprocess.run(['sudo','-k','-n','true'],capture_output=True).returncode==0:
        raise ValueError('Existing sudo rules permit passwordless sudo; refusing to claim password-required policy')
    if secret:
        check=subprocess.run(['sudo','-k','-S','-p','','-v'],input=secret+'\n',text=True,capture_output=True)
        if check.returncode:raise ValueError('Could not authenticate for sudo')
    cmd=['sudo','-n',sys.executable,'-c',script]
r=subprocess.run(cmd,input=json.dumps(p),text=True)
sys.exit(r.returncode)
'''


@dataclass
class Setup:
    new_user: str
    keypath: str
    public_key: str
    recovery_password: str = field(repr=False)
    bootstrap_password: str = field(default='',repr=False)
    passwordless: bool = True
    lock_root: bool = True
    block_bootstrap: bool = True
    key_only: bool = True
    new_port: int | None = None
    reuse_existing: bool = False
    bootstrap_key: str = field(default="",repr=False)
    generated_password: bool = False
    resume_setup_id: str = ""
    setup_id: str = field(default_factory=lambda:secrets.token_hex(16))
    token: str = field(default_factory=lambda:secrets.token_urlsafe(32),repr=False)

    def payload(self, op, bootstrap_user):
        return dict(op=op,new_user=self.new_user,public_key=self.public_key,recovery_password=self.recovery_password,bootstrap_user=bootstrap_user,setup_id=self.setup_id,token=self.token,passwordless=self.passwordless,lock_root=self.lock_root,block_bootstrap=self.block_bootstrap,key_only=self.key_only,new_port=self.new_port,reuse_existing=self.reuse_existing,resume_setup_id=self.resume_setup_id,_script=REMOTE_SCRIPT)


@contextmanager
def askpass(password,user,kind="login"):
    if not password:
        yield os.environ.copy()
        return
    if os.name=='nt':
        raise ValueError('Password bootstrap currently needs macOS/Linux. On Windows, use an existing administrator SSH key.')
    # Only a token and the ephemeral local port go in the environment; the
    # password is returned once over a loopback connection to our helper.
    with tempfile.TemporaryDirectory(prefix='sm-auth-') as directory:
        path=Path(directory)/'askpass'
        path.write_text('#!/bin/sh\nexec '+shlex.quote(sys.executable)+' -m ssh_manager.askpass "$@"\n')
        path.chmod(0o700)
        listener=socket.socket()
        listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(0.25)
        token=secrets.token_hex(32);stop=threading.Event()
        def answer():
            while not stop.is_set():
                try:conn,_=listener.accept()
                except socket.timeout:continue
                except OSError:return
                with conn:
                    conn.settimeout(3)
                    try:
                        supplied=conn.makefile('rb').readline(256).decode().strip()
                        if secrets.compare_digest(supplied,token):
                            conn.sendall((json.dumps(password)+'\n').encode())
                            return
                    except (OSError,UnicodeError):pass
        worker=threading.Thread(target=answer,daemon=True);worker.start()
        env={**os.environ,'SSH_ASKPASS':str(path),'SSH_ASKPASS_REQUIRE':'force','DISPLAY':os.environ.get('DISPLAY') or ':0','SM_ASKPASS_PORT':str(listener.getsockname()[1]),'SM_ASKPASS_TOKEN':token,'SM_LOGIN_USER':user,'SM_ASKPASS_KIND':kind}
        try:yield env
        finally:stop.set();listener.close();worker.join(timeout=1)


class SecureTransport:
    def __init__(self, config, host, plan):
        self.config,self.host,self.plan=config,host,plan
        self.active_port=host.port
        self.host_key_alias=host.host_key_alias or (host.hostname if host.port==22 else "["+host.hostname+"]:"+str(host.port))

    def arguments(self, new_user=False, port=None):
        h=self.host
        common=['ssh','-o','StrictHostKeyChecking='+('yes' if new_user else 'accept-new'),'-o','ControlMaster=no','-o','ControlPath=none','-o','ConnectTimeout=10','-o','ServerAliveInterval=10','-o','ServerAliveCountMax=2']
        if new_user:
            return common+['-F',os.devnull,'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no','-o','HostKeyAlias='+self.host_key_alias,'-i',self.plan.keypath,'-p',str(port or self.active_port),'-l',self.plan.new_user,'--',h.hostname]
        if self.plan.bootstrap_key:
            common+=['-i',self.plan.bootstrap_key,'-o','IdentitiesOnly=yes']
        return common+['-F',str(self.config.path),'-o','BatchMode=no' if self.plan.bootstrap_password else 'BatchMode=yes','-o','NumberOfPasswordPrompts=1','--',h.alias]

    def authorise_key(self):
        """Add a key using current credentials without provisioning or SSH policy edits."""
        from .remote import SCRIPT
        password=self.plan.bootstrap_password
        payload=dict(op='add-key',user=self.host.user,login_user=self.host.user,key=self.plan.public_key,_script=SCRIPT,_sudo_password=password)
        with askpass(password,self.host.user) as env:
            result=subprocess.run([*self.arguments(False),'python3 -c '+shlex.quote(WRAPPER)],input=json.dumps(payload),capture_output=True,text=True,env=env,timeout=75,start_new_session=os.name!='nt')
        if result.returncode:
            message=(result.stderr or 'SSH key authorisation failed').strip()[-1400:]
            for secret in (password,self.plan.recovery_password,self.plan.token):
                if secret:message=message.replace(secret,'[redacted]')
            if 'Traceback (most recent call last)' in message:message=message.splitlines()[-1]
            raise RuntimeError(message)
        return result.stdout.strip()

    def use_port(self, port):
        self.active_port=int(port)

    def run(self, op):
        try:
            return self._run(op,self.active_port)
        except (RuntimeError,subprocess.TimeoutExpired):
            if op in ('status','rollback') and self.active_port!=self.host.port:
                return self._run(op,self.host.port)
            raise

    def run_timed(self, op, timeout):
        deadline=time.monotonic()+timeout
        ports=[self.active_port]
        if op in ('status','rollback') and self.active_port!=self.host.port:ports.append(self.host.port)
        for index,port in enumerate(ports):
            budget=max(.1,deadline-time.monotonic())
            try:return self._run(op,port,timeout=budget/(len(ports)-index))
            except (RuntimeError,subprocess.TimeoutExpired):
                if index==len(ports)-1:raise

    def _run(self, op, port, timeout=None):
        new=op!='prepare'
        password='' if new else self.plan.bootstrap_password
        payload=self.plan.payload(op,self.host.user)
        payload['_sudo_password']=self.plan.recovery_password if new and (not self.plan.passwordless or self.plan.reuse_existing) else self.plan.bootstrap_password if not new and self.host.user!='root' else ''
        payload['_expect_password']=new and not self.plan.passwordless and not self.plan.reuse_existing
        temporary=tempfile.TemporaryDirectory(prefix='sm-bootstrap-key-') if not new and self.plan.bootstrap_key else nullcontext(None)
        with temporary as folder, askpass(password,self.host.user) as env:
            arguments=self.arguments(new,port)
            if folder:
                original=Path(self.plan.bootstrap_key).expanduser()
                protected=Path(folder)/'key'
                fd=os.open(protected,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                with os.fdopen(fd,'wb') as output:output.write(original.read_bytes())
                arguments[arguments.index('-i')+1]=str(protected)
            result=subprocess.run([*arguments,'python3 -c '+shlex.quote(WRAPPER)],input=json.dumps(payload),capture_output=True,text=True,env=env,timeout=timeout if timeout is not None else 600 if op=='prepare' else 75,start_new_session=os.name!='nt')
        if result.returncode:
            message=(result.stderr or 'SSH setup command failed').strip()[-1400:]
            # Neither wrapper nor helper prints request data. Redact defensively
            # in case a server's authentication hooks echo supplied credentials.
            for secret in (self.plan.bootstrap_password,self.plan.recovery_password,self.plan.token):
                if secret:message=message.replace(secret,'[redacted]')
            if 'Host key verification failed' in message:
                message='Server identity verification failed. A changed fingerprint must be checked before retrying setup. '+message
            if 'Traceback (most recent call last)' in message:
                message=message.splitlines()[-1]
                if message.startswith(('ValueError: ','RuntimeError: ')):message=message.split(': ',1)[1]
            raise RuntimeError(message)
        try:return json.loads(result.stdout)
        except ValueError:raise RuntimeError('Server returned an unexpected setup response; check Activity and server state.') from None


async def provision(transport, save_config, audit, progress, recovery=None):
    """No SSH restriction is applied before independent key login plus sudo."""
    import asyncio
    applied=False
    commit_requested=False
    async def timed(op,seconds):
        if hasattr(transport,'run_timed'):
            return await asyncio.to_thread(transport.run_timed,op,seconds)
        return await asyncio.to_thread(transport.run,op)
    async def reconnect(phase):
        deadline=time.monotonic()+RECONNECT_WINDOW_SECONDS
        last_error=None
        first=True
        while first or time.monotonic()<deadline:
            first=False
            remaining=max(0,deadline-time.monotonic())
            task=asyncio.create_task(timed('verify',min(5,max(.1,remaining))))
            while not task.done():
                if recovery:recovery(str(last_error) if last_error else '',max(0,math.ceil(deadline-time.monotonic())))
                await asyncio.wait({task},timeout=min(1,max(.01,deadline-time.monotonic())))
            try:
                checked=await task
                if checked.get('phase')!=phase or checked.get('login')!=transport.plan.new_user or checked.get('sudo') is not True:
                    raise RuntimeError('Post-change login verification failed')
                if recovery:recovery('',None)
                return checked
            except Exception as error:
                last_error=RuntimeError('SSH connection timed out') if isinstance(error,subprocess.TimeoutExpired) else error
                if recovery:recovery(str(last_error),max(0,math.ceil(deadline-time.monotonic())))
                if time.monotonic()>=deadline:raise
                await asyncio.sleep(min(1,max(0,deadline-time.monotonic())))
        raise RuntimeError('SSH reconnection failed within 30 seconds: '+str(last_error))
    try:
        progress('Checking the current account and authorising its key…' if getattr(transport.plan,'reuse_existing',False) else 'Creating the new account and authorising its key…')
        prepared=await asyncio.to_thread(transport.run,'prepare')
        audit('Account prepared',prepared.get('backup',''))
        progress('Verifying a fresh key login and sudo access…')
        verified=await asyncio.to_thread(transport.run,'verify')
        if verified.get('login')!=transport.plan.new_user or verified.get('sudo') is not True:
            raise RuntimeError('The new account did not pass login and sudo verification. Original SSH access retained.')
        audit('New login verified','Independent key login and selected sudo policy succeeded')
        progress('Applying SSH restrictions with a five-minute recovery timer…')
        # An interrupted response can still mean the server applied the change.
        applied=True
        await asyncio.to_thread(transport.run,'apply')
        new_port=getattr(transport.plan,'new_port',None)
        if new_port:
            transport.use_port(new_port)
            progress(f'Verifying a fresh login on SSH port {new_port}…')
        else:
            progress('Reconnecting to verify the restricted SSH configuration…')
        await reconnect('applied')
        if new_port:
            progress('New port verified; retiring the old listening port…')
            await asyncio.to_thread(transport.run,'finish-port')
            await reconnect('port-finalized')
        progress('Saving the updated connection…')
        await save_config()
        progress('Finalising setup and cancelling the recovery timer…')
        commit_requested=True
        committed=await asyncio.to_thread(transport.run,'commit')
        if committed.get('phase')!='committed':raise RuntimeError('Setup was not committed')
        applied=False
        audit('Secure setup complete',committed.get('backup',''))
        return committed
    except Exception:
        if applied:
            if commit_requested:
                try:
                    status=await timed('status',5)
                    if status.get('phase')=='committed':
                        audit('Secure setup complete',status.get('backup',''))
                        return status
                except Exception:
                    pass
            try:
                if recovery:recovery('SSH verification failed. Attempting rollback now.',0)
                progress('Attempting SSH rollback via the new or original port…')
                result=await timed('rollback',20)
                audit('SSH policy rolled back',result.get('phase','Recovery requested'))
            except Exception:
                audit('Recovery pending','Server-side five-minute timer will attempt to restore previous SSH access. Use the VM console if necessary.')
        raise
