"""Debian/Ubuntu setup helper, sent to the server over authenticated SSH stdin.
No credential is placed in a command argument, policy file, state file or log.
"""
from .remote import SCRIPT
from .secure_ports import PORT_HELPERS

# Reuse the existing user/key helper, including its privilege drop for home files.
REMOTE_SCRIPT = SCRIPT.split("op=p['op']", 1)[0] + PORT_HELPERS + r'''
import grp, uuid
BASE='/var/lib/ssh-manager'
LEGACY_BASE='/var/lib/server-manager'  # Previous releases' recovery records.
MAIN='/etc/ssh/sshd_config'
SSHD='/usr/sbin/sshd'

def command(args,timeout=30,**kwargs):
    r=subprocess.run(args,capture_output=True,text=True,timeout=timeout,**kwargs)
    if r.returncode:raise RuntimeError('Command failed: '+str(args[0])+'; '+r.stderr.strip()[-800:])
    return r.stdout.strip()

def write(path,content,mode=0o600):
    directory=os.path.dirname(path)
    fd,tmp=tempfile.mkstemp(dir=directory)
    try:
        os.fchmod(fd,mode)
        with os.fdopen(fd,'w') as out:out.write(content);out.flush();os.fsync(out.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def save(state):write(os.path.join(state['directory'],'state.json'),json.dumps(state))

def load():
    ident=p['setup_id']
    if not re.fullmatch(r'[a-f0-9]{32}',ident):raise ValueError('Invalid setup identifier')
    directory=os.path.join(BASE,ident)
    state=json.load(open(os.path.join(directory,'state.json')))
    if state['token']!=p['token']:raise ValueError('Setup token mismatch')
    return state

def service():
    for name in ('ssh.service','sshd.service'):
        r=subprocess.run(['systemctl','is-active','--quiet',name])
        if r.returncode==0:return name
    raise ValueError('An active systemd SSH service is required for automatic rollback')

def validate_name(name):
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',name) or name=='root':raise ValueError('Choose a normal Debian/Ubuntu username')

def effective(user,connection):
    parts=connection.split()
    if len(parts)!=4:raise ValueError('Cannot determine SSH connection context for policy checks')
    context='user='+user+',host='+parts[0]+',addr='+parts[0]+',laddr='+parts[2]+',lport='+parts[3]
    result=command([SSHD,'-T','-C',context])
    values={}
    for line in result.splitlines():
        if ' ' not in line:continue
        key,value=line.split(' ',1)
        values[key]=values.get(key,'')+' '+value if key in ('denyusers','allowusers','denygroups','allowgroups','port') else value
    return values

def check_policy(state):
    command([SSHD,'-t'])
    connection=p.get('_connection') or state['connection']
    new=effective(state['new_user'],connection)
    if state.get('new_port'):
        expected={state['new_port']} if state['phase']=='port-finalized' else {state['old_port'],state['new_port']}
        if {int(value) for value in new.get('port','').split()}!=expected:raise ValueError('Effective SSH ports do not match the requested handover')
    required=[('pubkeyauthentication','yes')]
    if state['key_only']:required += [('passwordauthentication','no'),('kbdinteractiveauthentication','no'),('authenticationmethods','publickey')]
    for name,value in required:
        if new.get(name)!=value:raise ValueError('Existing SSH rules conflict with key-only login: '+name)
    root=effective('root',connection)
    if state['lock_root'] and root.get('permitrootlogin')!='no':raise ValueError('Existing Match rules override root SSH restriction')
    if state['block_bootstrap']:
        old=effective(state['bootstrap_user'],connection)
        if state['bootstrap_user'] not in old.get('denyusers','').split():raise ValueError('Original SSH login was not denied')

# Standalone, root-owned timed recovery; no client process needs to remain alive.
ROLLBACK = r"""
import fcntl,json,os,subprocess,sys,tempfile,time
folder=sys.argv[1]
with open(folder+'/state.lock','a') as lock:
    fcntl.flock(lock,fcntl.LOCK_EX)
    state=json.load(open(folder+'/state.json'))
    if state['phase'] not in ('armed','applied','port-finalized'):sys.exit(0)
    path=state['main'];prefix=state['include']
    current=open(path).read()
    restored=current.replace(prefix,'',1).replace(state['suffix'],'',1) if state.get('suffix') else current.replace(prefix,'',1)
    def write(path,value,mode):
        fd,tmp=tempfile.mkstemp(dir=os.path.dirname(path));os.fchmod(fd,mode)
        with os.fdopen(fd,'w') as out:out.write(value);out.flush();os.fsync(out.fileno())
        os.replace(tmp,path)
    write(path,restored,state['mode'])
    for item in state.get('port_files',[]):
        content=open(item['path']).read()
        for change in item['changes']:content=content.replace(change['managed'],change['original'],1)
        write(item['path'],content,item['mode'])
    override=state.get('socket_override')
    if override and os.path.exists(override):os.unlink(override)
    if os.path.exists(state['policy']):os.unlink(state['policy'])
    if subprocess.run([state['sshd'],'-t'],capture_output=True).returncode:
        write(folder+'/config-at-rollback',current,0o600)
        for item in state.get('port_files',[]):write(item['path'],open(item['before']).read(),item['mode'])
        write(path,open(folder+'/sshd_config.before').read(),state['mode'])
    if subprocess.run([state['sshd'],'-t'],capture_output=True).returncode:
        state['phase']='rollback-needs-console'
    else:
        if state.get('socket_unit'):
            subprocess.run(['systemctl','daemon-reload'],capture_output=True)
            r=subprocess.run(['systemctl','restart',state['socket_unit'],state['service']],capture_output=True)
        else:r=subprocess.run(['systemctl','reload',state['service']],capture_output=True)
        state['phase']='rolled-back' if r.returncode==0 else 'rollback-needs-console'
    write(folder+'/state.json',json.dumps(state),0o600)
"""

def rollback(state):
    result=subprocess.run([sys.executable,state['directory']+'/rollback.py',state['directory']],capture_output=True,text=True,timeout=30)
    if result.returncode:raise RuntimeError('Automatic rollback failed; use the VM console and saved backup')
    restored=json.load(open(state['directory']+'/state.json'))
    if restored['phase']=='rollback-needs-console':raise RuntimeError('Recovery needs the VM console; backups are in '+state['directory'])
    return restored

def resumable_account(name,key):
    if not p.get('resume_setup_id'):return None
    user=pwd.getpwnam(name)
    if user.pw_uid<1000 or user.pw_uid>=65534:return None
    for folder in sorted(glob.glob(BASE+'/*')+glob.glob(LEGACY_BASE+'/*')):
        if not re.fullmatch(r'[a-f0-9]{32}',os.path.basename(folder)):continue
        try:
            state=json.load(open(folder+'/state.json'))
            if state.get('new_user')!=name or state.get('bootstrap_user')!=p['bootstrap_user'] or state.get('reuse_existing'):continue
            if keyparts(open(folder+'/key.pub').read())!=keyparts(key):continue
            if state.get('created_uid') is not None and state['created_uid']!=user.pw_uid:continue
            if state.get('phase') in ('armed','applied','port-finalized'):
                raise ValueError('Recovery is still pending for this account. Wait for the five-minute rollback before retrying.')
            if state.get('phase') not in ('prepared','rolled-back'):continue
            _,_,authorized=keyfile(name)
            if not any(keyparts(line)==keyparts(key) for line in open(authorized)):continue
            prefix='99-server-manager-' if os.path.dirname(folder)==LEGACY_BASE else '99-ssh-manager-'
            sudoers=state.get('sudoers_path') or '/etc/sudoers.d/'+prefix+name
            if open(sudoers).read()!=open(folder+'/sudoers').read():continue
            state['_resume_sudoers_path']=sudoers
            return state
        except (OSError,KeyError,json.JSONDecodeError):continue
    return None


def prepare():
    name=p['new_user'];reuse=bool(p.get('reuse_existing'))
    if reuse:
        if name!=p['bootstrap_user'] or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*\$?',name):raise ValueError('Existing account must match the current login')
        pwd.getpwnam(name)
        if name=='root' and (p['lock_root'] or p['block_bootstrap']):raise ValueError('Cannot disable the root account while retaining it as the login')
        if p['block_bootstrap']:raise ValueError('Cannot disable the account that is being retained')
    else:
        validate_name(name)
        if name==p['bootstrap_user']:raise ValueError('The new user must differ from the original login')
    release={}
    for line in open('/etc/os-release'):
        if '=' in line:
            k,v=line.strip().split('=',1);release[k]=v.strip('"')
    if release.get('ID') not in ('debian','ubuntu'):raise ValueError('Automatic setup currently supports Debian and Ubuntu only')
    if not shutil.which('systemd-run') or not shutil.which('systemctl'):raise ValueError('systemd is required for timed rollback')
    ssh_service=service()
    command([SSHD,'-t'])
    port_details=plan_ports(p['_connection'],ssh_service)
    original=open(MAIN).read()
    original_hash=hashlib.sha256(original.encode()).hexdigest()
    key=p['public_key']
    resumed=None
    if not reuse:
        try:pwd.getpwnam(name)
        except KeyError:pass
        else:
            resumed=resumable_account(name,key)
            if resumed is None:raise ValueError('That account already exists; no matching recoverable setup was found. Choose another username or use the existing-account option.')
    if '\n' in key or not keyparts(key):raise ValueError('Invalid public key')
    recovery=p['recovery_password']
    if not reuse and ((len(recovery)<16 and not re.fullmatch(r'[a-z0-9]{6}-[a-z0-9]{6}',recovery)) or any(c in recovery for c in '\n\r')):raise ValueError('Use a generated xxxxxx-xxxxxx lowercase/digit password or at least 16 characters')
    ident=p['setup_id']
    if not re.fullmatch(r'[a-f0-9]{32}',ident):raise ValueError('Invalid setup identifier')
    os.makedirs(BASE,mode=0o700,exist_ok=True)
    directory=os.path.join(BASE,ident);os.mkdir(directory,0o700)
    state=dict(directory=directory,token=p['token'],new_user=name,bootstrap_user=p['bootstrap_user'],connection=p['_connection'],phase='preparing',main=os.path.realpath(MAIN),mode=os.stat(MAIN).st_mode&0o777,original_hash=original_hash,service=ssh_service,sshd=SSHD,unit='ssh-manager-rollback-'+ident,policy='/etc/ssh/ssh-manager-'+ident+'.conf',passwordless=p['passwordless'],lock_root=p['lock_root'],block_bootstrap=p['block_bootstrap'],key_only=p['key_only'],reuse_existing=reuse)
    backup_ports(state,port_details)
    save(state)
    write(directory+'/sshd_config.before',original)
    write(directory+'/key.pub',key+'\n')
    command(['ssh-keygen','-lf',directory+'/key.pub'])
    if not shutil.which('sudo'):
        command(['apt-get','update'],timeout=240,env={**os.environ,'DEBIAN_FRONTEND':'noninteractive'})
        command(['apt-get','install','-y','sudo'],timeout=240,env={**os.environ,'DEBIAN_FRONTEND':'noninteractive'})
    if not shutil.which('visudo'):raise ValueError('sudo/visudo is unavailable')
    if not reuse:
        try:grp.getgrnam('sudo')
        except KeyError:command(['groupadd','sudo'])
        sudoers=resumed.get('_resume_sudoers_path') if resumed else '/etc/sudoers.d/99-ssh-manager-'+name
        state['sudoers_path']=sudoers
        if os.path.lexists(sudoers) and not resumed:raise ValueError('A sudo rule for that username already exists')
        os.makedirs('/etc/sudoers.d',mode=0o755,exist_ok=True)
        rule=name+' ALL=(ALL:ALL) '+('NOPASSWD' if p['passwordless'] else 'PASSWD')+': ALL\n'
        write(directory+'/sudoers',rule,0o440)
        command(['visudo','-cf',directory+'/sudoers'])
        if not resumed:
            command(['useradd','--create-home','--shell','/bin/bash','--groups','sudo','--',name])
        state['created_uid']=pwd.getpwnam(name).pw_uid
        save(state)
        command(['chpasswd'],input=name+':'+recovery+'\n')
        change_key(name,key)
        write(sudoers,rule,0o440)
        try:command(['visudo','-c'])
        except Exception:
            os.unlink(sudoers);raise
    else:
        # Keep the existing account, password, groups and sudoers policy.
        change_key(name,key)
    state['phase']='prepared';save(state)
    return dict(phase='prepared',backup=directory,installed_sudo=True,new_user=name)

def verify(state):
    if p.get('_actual_user')!=state['new_user']:raise ValueError('Verification must use a fresh login as the new user')
    u=pwd.getpwnam(state['new_user'])
    if not state.get('reuse_existing') and grp.getgrnam('sudo').gr_gid not in os.getgrouplist(u.pw_name,u.pw_gid):raise ValueError('New user is not in the sudo group')
    if state['phase'] in ('armed','applied','port-finalized'):check_policy(state)
    if state['phase']=='prepared':state['verified']=True;save(state)
    if state['phase']=='applied' and state.get('new_port') and int(p['_connection'].split()[3])==state['new_port']:
        state['new_port_verified']=True;save(state)
    return dict(phase=state['phase'],login=state['new_user'],sudo=True)

def apply(state):
    if state['phase']!='prepared' or not state.get('verified'):raise ValueError('New login and sudo must be verified before SSH restrictions')
    if p.get('_actual_user')!=state['new_user']:raise ValueError('Apply must use the new account')
    check_port_sources(state)
    original=open(state['main']).read()
    if hashlib.sha256(original.encode()).hexdigest()!=state['original_hash']:raise ValueError('SSH configuration changed during setup; original access retained')
    include='Include '+state['policy']+'\n'
    state['include']=include
    state['suffix']='\n# BEGIN ssh-manager '+os.path.basename(state['directory'])+'\nMatch User '+state['new_user']+'\n    PubkeyAuthentication yes\n'
    if state['key_only']:state['suffix']+='    PasswordAuthentication no\n    KbdInteractiveAuthentication no\n    AuthenticationMethods publickey\n'
    state['suffix']+='# END ssh-manager\n'
    write(state['directory']+'/rollback.py',ROLLBACK,0o700)
    state['phase']='armed';save(state)
    try:
        command(['systemd-run','--quiet','--unit='+state['unit'],'--on-active=300s','--timer-property=AccuracySec=1s',sys.executable,state['directory']+'/rollback.py',state['directory']])
    except Exception:
        state['phase']='prepared';save(state);raise
    policy='PermitRootLogin no\n' if state['lock_root'] else '# SSH Manager SSH policy\n'
    if state['lock_root']:policy+='DenyUsers root\n'
    if state['block_bootstrap'] and (state['bootstrap_user']!='root' or not state['lock_root']):policy+='DenyUsers '+state['bootstrap_user']+'\n'
    try:
        state['base_policy']=policy;save(state)
        if state.get('new_port'):
            mark_original_ports(state)
            policy=managed_port_policy(state)
        write(state['policy'],policy)
        write(state['main'],include+open(state['main']).read()+state['suffix'],state['mode'])
        check_policy(state)
        if state.get('new_port'):activate_ports(state)
        else:command(['systemctl','reload',state['service']])
        state['phase']='applied';save(state)
        return dict(phase='applied',rollback_seconds=300,backup=state['directory'])
    except Exception:
        rollback(state);raise

def commit(state):
    if state['phase'] not in ('applied','port-finalized') or p.get('_actual_user')!=state['new_user']:raise ValueError('A fresh new-user connection must confirm the applied policy')
    if state.get('new_port') and state['phase']!='port-finalized':raise ValueError('New port must be finalized before committing')
    check_policy(state)
    with open(state['directory']+'/state.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        current=json.load(open(state['directory']+'/state.json'))
        if current['phase'] not in ('applied','port-finalized'):raise ValueError('Timed rollback already ran; setup is not committed')
        current['phase']='committed';save(current)
    subprocess.run(['systemctl','stop',state['unit']+'.timer'],capture_output=True)
    return dict(phase='committed',backup=state['directory'])

if os.geteuid()!=0:raise ValueError('Administrative privileges are required')
op=p['op']
if op=='prepare':result=prepare()
else:
    state=load()
    if op=='verify':result=verify(state)
    elif op=='apply':result=apply(state)
    elif op=='finish-port':result=finish_port(state)
    elif op=='commit':result=commit(state)
    elif op=='status':result=dict(phase=state['phase'],backup=state['directory'])
    elif op=='rollback':result=dict(phase=rollback(state)['phase'])
    else:raise ValueError('Unknown setup phase')
print(json.dumps(result))
'''
