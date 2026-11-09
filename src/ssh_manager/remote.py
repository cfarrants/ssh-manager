"""Remote operations use OpenSSH, strict host verification and no password logs."""
from __future__ import annotations
import json
import os
from pathlib import Path
import shlex
import subprocess

# Executed only after an explicit operation in the interface. Passwords travel
# over SSH stdin, never command arguments. Debian/Ubuntu require Python 3.
SCRIPT = r'''
import base64, contextlib, fcntl, glob, hashlib, ipaddress, json, os, pwd, re, shlex, shutil, socket, subprocess, sys, tempfile, time
p=json.load(sys.stdin)
def keyparts(line):
    try:
        bits=shlex.split(line)
        for i,b in enumerate(bits[:-1]):
            if b.startswith(('ssh-', 'ecdsa-', 'sk-')):
                return b,bits[i+1]
    except ValueError: pass
    return None

def keyinfo(line):
    parts=keyparts(line)
    if not parts: return None
    try: fp='SHA256:'+base64.b64encode(hashlib.sha256(base64.b64decode(parts[1])).digest()).decode().rstrip('=')
    except Exception: return None
    return dict(fingerprint=fp,public_key=' '.join(parts),line=line)

def keyfile(user):
    u=pwd.getpwnam(user)
    directory=os.path.join(u.pw_dir,'.ssh')
    path=os.path.join(directory,'authorized_keys')
    if os.path.islink(u.pw_dir) or os.path.islink(directory) or os.path.islink(path):
        raise ValueError('Symlinked home/.ssh/authorized_keys requires manual administration')
    return u,directory,path

def change_key(user,key,remove=False):
    u,directory,path=keyfile(user)
    # Operate on user-controlled paths as that user, so even a concurrent
    # directory replacement cannot turn a key update into a privileged write.
    if os.geteuid()==0 and u.pw_uid!=0:
        child=os.fork()
        if child==0:
            try:
                os.initgroups(user,u.pw_gid);os.setgid(u.pw_gid);os.setuid(u.pw_uid)
                change_key(user,key,remove)
                os._exit(0)
            except Exception as error:
                print(str(error),file=sys.stderr,flush=True);os._exit(1)
        _,status=os.waitpid(child,0)
        if os.waitstatus_to_exitcode(status)!=0:
            raise RuntimeError('Key update failed as the target user; check home/.ssh ownership and permissions')
        return 'Key revoked' if remove else 'Key authorised'
    new=keyparts(key)
    if not new: raise ValueError('Invalid public key')
    os.makedirs(directory,mode=0o700,exist_ok=True)
    os.chown(directory,u.pw_uid,u.pw_gid)
    os.chmod(directory,0o700)
    # Keep the same file lock when interoperating with previous releases.
    lockpath=os.path.join(directory,'.server-manager.lock')
    fd=os.open(lockpath,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        lines=open(path).read().splitlines() if os.path.exists(path) else []
        if remove:
            lines=[line for line in lines if keyparts(line)!=new]
        elif not any(keyparts(line)==new for line in lines): lines.append(key)
        if os.path.exists(path):
            backup=path+'.ssh-manager-'+str(time.time_ns())+'.bak'
            shutil.copy2(path,backup);os.chmod(backup,0o600)
        fd,tmp=tempfile.mkstemp(dir=directory)
        try:
            os.fchown(fd,u.pw_uid,u.pw_gid);os.fchmod(fd,0o600)
            with os.fdopen(fd,'w') as out:
                out.write('\n'.join(lines)+'\n');out.flush();os.fsync(out.fileno())
            os.replace(tmp,path)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
    return 'Key revoked' if remove else 'Key authorised'

op=p['op']
if op=='inspect-keys':
    user,directory,path=keyfile(p['user'])
    keys=[key for line in open(path) if (key:=keyinfo(line.strip()))] if os.path.exists(path) else []
    print(json.dumps(dict(user=user.pw_name,keys=keys)))
elif op=='inspect':
    users=[]
    for u in pwd.getpwall():
        if u.pw_uid==0 or (u.pw_uid>=1000 and u.pw_uid<65534):
            keys=[]
            try:
                _,_,path=keyfile(u.pw_name)
                if os.path.exists(path): keys=[k for line in open(path) if (k:=keyinfo(line.strip()))]
            except (OSError,ValueError): pass
            users.append(dict(user=u.pw_name,uid=u.pw_uid,home=u.pw_dir,shell=u.pw_shell,keys=keys))
    domains=set()
    for pattern in ('/etc/nginx/sites-enabled/*','/etc/nginx/conf.d/*.conf','/etc/apache2/sites-enabled/*'):
        for file in glob.glob(pattern):
            if not os.path.isfile(file):continue
            text=open(file,errors='replace').read()
            for match in re.finditer(r'(?im)^\s*(?:server_name|ServerName|ServerAlias)\s+([^;\n]+)',text):
                for name in match.group(1).split():
                    if re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}',name):domains.add(name.lower())
    addresses=[]
    try:
        result=subprocess.run(['ip','-j','address','show'],capture_output=True,text=True,timeout=5)
        addresses=[a['local'] for interface in json.loads(result.stdout) for a in interface.get('addr_info',[]) if ipaddress.ip_address(a['local']).is_global]
    except Exception:pass
    print(json.dumps(dict(users=users,domains=sorted(domains),interface_public_ips=sorted(set(addresses)),hostname=socket.gethostname())))
elif op in ('add-key','revoke-key'):
    print(change_key(p['user'],p['key'],op=='revoke-key'))
elif op=='create-user':
    name=p['user']
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',name):raise ValueError('Invalid Debian/Ubuntu username')
    subprocess.run(['useradd','--create-home','--shell','/bin/bash','--',name],check=True)
    if p.get('key'):change_key(name,p['key'])
    print('User created; password login remains locked until a password is set')
elif op=='delete-user':
    u=pwd.getpwnam(p['user'])
    if u.pw_uid<1000 or u.pw_uid>=65534 or u.pw_name==p['login_user']:raise ValueError('Cannot remove a system account or the connected account')
    subprocess.run(['userdel','--',u.pw_name],check=True)
    print('User removed; home directory retained')
elif op=='password':
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',p['user']):raise ValueError('Invalid username')
    password=p['password']
    if '\n' in password or '\r' in password:raise ValueError('Password must not contain newlines')
    pwd.getpwnam(p['user'])
    subprocess.run(['chpasswd'],input=p['user']+':'+password+'\n',text=True,check=True)
    print('Password updated')
else:raise ValueError('Unknown operation')
'''


class Remote:
    def __init__(self, config, password_provider=None):
        self.config = config
        self.password_provider = password_provider

    def base(self, alias):
        return ["ssh", "-F", str(self.config.path), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2", "--", alias]

    def run(self, host, op, **values):
        payload = {"op": op, "login_user": host.user, **values}
        prefix = "" if host.user == "root" else "sudo -n "
        command = prefix + "python3 -c " + shlex.quote(SCRIPT)
        sudo_password = self.password_provider(host) if host.user != 'root' and self.password_provider else ''
        if sudo_password:
            from .secure import WRAPPER
            payload.update(_script=SCRIPT, _sudo_password=sudo_password)
            command = 'python3 -c '+shlex.quote(WRAPPER)
        result = subprocess.run([*self.base(host.alias), command], input=json.dumps(payload), capture_output=True, text=True, timeout=75)
        if result.returncode:
            # Never echo stdin/payload. The remote script does not log passwords.
            message = (result.stderr or "SSH operation failed").strip()[-1800:]
            for secret in (sudo_password, values.get('password', '')):
                if secret:
                    message = message.replace(secret, '[redacted]')
            raise RuntimeError(message)
        return json.loads(result.stdout) if op in ("inspect","inspect-keys") else result.stdout.strip()

    def verify_key(self, host, keypath):
        # A separate empty config prevents other configured IdentityFiles or an
        # existing multiplexed session from making the new-key check pass.
        import os
        command = ["ssh", "-F", os.devnull, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "IdentitiesOnly=yes", "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ConnectTimeout=8", "-i", str(keypath), "-p", str(host.port), "-l", host.user]
        if host.host_key_alias:
            command.extend(["-o", "HostKeyAlias="+host.host_key_alias])
        if host.proxy:
            # Complex proxy policies should not be approximated in a rotation.
            raise ValueError("Rotation through a proxy requires a manual new-key check; old keys were retained.")
        command.extend(["--", host.hostname, "true"])
        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
        if result.returncode:
            raise RuntimeError("New key did not authenticate independently. Old key retained. Unlock the new key in ssh-agent or verify manually if it has a passphrase. " + result.stderr.strip()[-500:])
        return True


def local_keys(directory, extra=()):
    rows = []
    paths = set(Path(directory).glob("*.pub"))
    paths.update((Path(directory)/'keys').glob('*.pub'))
    for value in extra:
        path = Path(value).expanduser()
        paths.add(path if path.suffix == ".pub" else path.with_name(path.name+".pub"))
    for path in sorted(paths):
        if not path.is_file():
            continue
        try:
            result = subprocess.run(["ssh-keygen", "-lf", str(path)], capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                bits = result.stdout.strip().split()
                rows.append({"path": str(path), "fingerprint": bits[1], "label": " ".join(bits[2:-1]), "type": bits[-1], "public_key": path.read_text().strip()})
        except OSError:
            pass
    return rows


def create_key(path, label, passphrase=None):
    path = Path(path).expanduser()
    if os.path.lexists(path) or os.path.lexists(path.with_name(path.name + ".pub")):
        raise ValueError("Key path already exists; nothing was overwritten.")
    if any(c in label for c in "\r\n"):
        raise ValueError("Label must be a single line.")
    if passphrase is not None and any(c in passphrase for c in "\r\n\x00"):
        raise ValueError("Passphrase must be a single line without null characters.")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Interactive passphrase stays in the user's terminal, never in process args.
    command=["ssh-keygen", "-t", "ed25519", "-C", label, "-f", str(path)]
    if passphrase is None:
        result = subprocess.run(command)
    else:
        # A detached terminal makes OpenSSH read both prompts from stdin.
        # The passphrase never appears in process arguments, files or the environment.
        result = subprocess.run(command,input=passphrase+'\n'+passphrase+'\n',text=True,capture_output=True,start_new_session=os.name!='nt',timeout=30)
    if result.returncode:
        raise RuntimeError("Key generation cancelled or failed.")
