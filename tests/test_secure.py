import asyncio
import io
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import subprocess
import pytest
from ssh_manager.secure import Setup, SecureTransport, provision, WRAPPER
from ssh_manager.secure_remote import REMOTE_SCRIPT
from ssh_manager.config import Host, SSHConfig


@pytest.fixture(autouse=True)
def fast_reconnect_window(monkeypatch):
    monkeypatch.setattr('ssh_manager.secure.RECONNECT_WINDOW_SECONDS',0)


class Transport:
    def __init__(self, fail=None, wrong_verify=False, committed_on_error=False):
        self.plan=SimpleNamespace(new_user='newadmin')
        self.calls=[];self.fail=fail;self.wrong_verify=wrong_verify;self.committed_on_error=committed_on_error
        self.verifications=0
    def run(self,op):
        self.calls.append(op)
        if op==self.fail:raise RuntimeError('simulated '+op+' failure')
        if op=='verify':
            self.verifications+=1
            return dict(login='wrong' if self.wrong_verify else 'newadmin',sudo=True,phase='prepared' if self.verifications==1 else 'applied')
        if op=='status':return dict(phase='committed' if self.committed_on_error else 'applied')
        if op=='rollback':return dict(phase='rolled-back')
        return dict(phase={'prepare':'prepared','apply':'applied','commit':'committed'}.get(op,op),backup='/backup')


@pytest.mark.asyncio
async def test_setup_order_requires_new_login_before_restrictions():
    transport=Transport();events=[]
    async def save():transport.calls.append('save-config')
    result=await provision(transport,save,lambda *x:events.append(x),lambda x:None)
    assert transport.calls==['prepare','verify','apply','verify','save-config','commit']
    assert result['phase']=='committed'


@pytest.mark.asyncio
@pytest.mark.parametrize('stage',['prepare','verify'])
async def test_early_failure_never_restricts_ssh(stage):
    transport=Transport(fail=stage)
    async def save():pytest.fail('must not change config')
    with pytest.raises(RuntimeError):await provision(transport,save,lambda *x:None,lambda x:None)
    assert 'apply' not in transport.calls and 'commit' not in transport.calls


@pytest.mark.asyncio
async def test_wrong_new_user_never_restricts_ssh():
    transport=Transport(wrong_verify=True)
    async def save():pytest.fail('must not change config')
    with pytest.raises(RuntimeError,match='verification'):await provision(transport,save,lambda *x:None,lambda x:None)
    assert 'apply' not in transport.calls


@pytest.mark.asyncio
async def test_lost_apply_response_requests_rollback():
    transport=Transport(fail='apply')
    async def save():pytest.fail('must not change config')
    with pytest.raises(RuntimeError):await provision(transport,save,lambda *x:None,lambda x:None)
    assert transport.calls[-1]=='rollback'


@pytest.mark.asyncio
async def test_post_change_connection_failure_requests_recovery():
    transport=Transport();original=transport.run
    def run(op):
        if op=='verify' and transport.verifications==1:
            transport.calls.append(op);raise RuntimeError('post-change connection failed')
        return original(op)
    transport.run=run
    async def save():pytest.fail('must not change config')
    with pytest.raises(RuntimeError):await provision(transport,save,lambda *x:None,lambda x:None)
    assert transport.calls[-1]=='rollback'


@pytest.mark.asyncio
async def test_local_config_conflict_keeps_recovery_available():
    transport=Transport()
    async def save():raise ValueError('outside edit')
    with pytest.raises(ValueError):await provision(transport,save,lambda *x:None,lambda x:None)
    assert 'commit' not in transport.calls and transport.calls[-1]=='rollback'


@pytest.mark.asyncio
async def test_lost_commit_response_checks_committed_state():
    transport=Transport(fail='commit',committed_on_error=True)
    async def save():pass
    result=await provision(transport,save,lambda *x:None,lambda x:None)
    assert result['phase']=='committed'
    assert 'rollback' not in transport.calls


def test_credentials_do_not_enter_arguments_or_environment(monkeypatch,tmp_path):
    captured=[]
    plan=Setup('newadmin','/private/key','ssh-ed25519 AAAA','recovery-password-secret','bootstrap-secret')
    host=Host('test',tmp_path/'config',0,1,['test'],'',hostname='localhost',user='root')
    def run(args,**kwargs):
        captured.append((args,kwargs));return SimpleNamespace(returncode=0,stdout='{"phase":"prepared"}',stderr='')
    monkeypatch.setattr('ssh_manager.secure.subprocess.run',run)
    SecureTransport(SSHConfig(tmp_path/'config'),host,plan).run('prepare')
    args,kwargs=captured[0]
    assert plan.bootstrap_password not in ' '.join(args)
    assert plan.recovery_password not in ' '.join(args)
    assert all(plan.bootstrap_password not in value for value in kwargs['env'].values())
    assert plan.bootstrap_password not in kwargs['input'] # root sudo does not need it
    assert plan.recovery_password in kwargs['input']
    assert 'bootstrap-secret' not in repr(plan)
    assert 'recovery-password-secret' not in repr(plan)


def test_new_key_verification_cannot_reuse_old_session(tmp_path):
    plan=Setup('newadmin','/private/key','ssh-ed25519 AAAA','a'*20,passwordless=False)
    host=Host('test',tmp_path/'config',0,1,['test'],'',hostname='localhost',user='root')
    transport=SecureTransport(SSHConfig(tmp_path/'config'),host,plan)
    args=transport.arguments(True)
    for option in ('ControlPath=none','IdentitiesOnly=yes','PasswordAuthentication=no','KbdInteractiveAuthentication=no','StrictHostKeyChecking=yes'):
        assert option in args
    assert args[args.index('-l')+1]=='newadmin'
    assert args[args.index('-i')+1]=='/private/key'


def load_helpers(tmp_path,monkeypatch):
    # All privileged paths are redirected into this temporary directory, and
    # every external command is replaced before any helper is invoked.
    root=tmp_path/'remote';root.mkdir()
    (root/'release').write_text('ID=debian\n')
    (root/'ssh').mkdir();(root/'ssh'/'sshd_config').write_text('# original\nPasswordAuthentication yes\n')
    source=REMOTE_SCRIPT[:REMOTE_SCRIPT.index("if os.geteuid()!=0:raise ValueError")]
    source=source.replace('/var/lib/ssh-manager',str(root/'state')).replace('/etc/ssh/',str(root/'ssh')+'/').replace('/etc/sudoers.d',str(root/'sudoers.d')).replace('/etc/apt/apt.conf.d',str(root/'apt')).replace('/etc/os-release',str(root/'release'))
    monkeypatch.setattr(sys,'stdin',io.StringIO('{}'))
    ns={};exec(compile(source,'<isolated secure helper>','exec'),ns)
    calls=[]
    def run(args,**kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=0,stdout='',stderr='')
    ns['subprocess']=SimpleNamespace(run=run)
    ns['command']=lambda args,**kwargs:run(args,**kwargs).stdout
    return root,ns,calls


@pytest.mark.parametrize('passwordless',[True,False])
def test_prepare_builds_selected_sudo_rule_without_changing_ssh(tmp_path,monkeypatch,passwordless):
    root,ns,calls=load_helpers(tmp_path,monkeypatch)
    original=(root/'ssh'/'sshd_config').read_text()
    plan=Setup('newadmin','/private/key','ssh-ed25519 AAAA','a'*24,passwordless=passwordless)
    ns['p']={**plan.payload('prepare','root'),'_connection':'127.0.0.1 2222 192.0.2.1 22'}
    lookups=iter([None,SimpleNamespace(pw_uid=1001)])
    def getuser(name):
        user=next(lookups)
        if user is None:raise KeyError(name)
        return user
    ns['pwd']=SimpleNamespace(getpwnam=getuser)
    ns['grp']=SimpleNamespace(getgrnam=lambda name:SimpleNamespace(gr_gid=42))
    ns['shutil']=SimpleNamespace(which=lambda name:'/fake/'+name)
    ns['change_key']=lambda user,key:calls.append(['authorise',user])
    result=ns['prepare']()
    rule=(root/'sudoers.d'/'99-ssh-manager-newadmin').read_text()
    assert ('NOPASSWD: ALL' if passwordless else 'PASSWD: ALL') in rule
    assert (root/'ssh'/'sshd_config').read_text()==original
    assert result['phase']=='prepared'
    assert not any(args[0]=='systemd-run' for args in calls)
    assert any(args[0]=='useradd' and 'sudo' in args for args in calls)
    state=(root/'state'/plan.setup_id/'state.json').read_text()
    assert plan.recovery_password not in state


def applied_state(root,ns):
    import hashlib
    directory=root/'pending';directory.mkdir()
    main=root/'ssh'/'sshd_config'
    state=dict(directory=str(directory),main=str(main),mode=0o600,original_hash=hashlib.sha256(main.read_bytes()).hexdigest(),phase='prepared',verified=True,new_user='newadmin',bootstrap_user='ubuntu',connection='127.0.0.1 2222 192.0.2.1 22',policy=str(root/'ssh'/'managed.conf'),unit='test-recovery',service='ssh.service',sshd='/fake/sshd',lock_root=True,block_bootstrap=True,key_only=True)
    (directory/'sshd_config.before').write_text(main.read_text())
    ns['p']={'_actual_user':'newadmin'}
    def effective(user,conn):
        return dict(pubkeyauthentication='yes',passwordauthentication='no',kbdinteractiveauthentication='no',authenticationmethods='publickey',permitrootlogin='no',denyusers='root ubuntu',allowagentforwarding='no',allowtcpforwarding='no')
    ns['effective']=effective
    return state


def test_apply_arms_timer_before_touching_ssh_and_commit_cancels_it(tmp_path,monkeypatch):
    root,ns,calls=load_helpers(tmp_path,monkeypatch)
    state=applied_state(root,ns);main=Path(state['main']);original=main.read_text()
    def command(args,**kwargs):
        calls.append(args)
        if args[0]=='systemd-run':assert main.read_text()==original
        return ''
    ns['command']=command
    result=ns['apply'](state)
    assert result['phase']=='applied'
    assert main.read_text().startswith('Include ')
    assert 'Match User newadmin' in main.read_text()
    assert 'PasswordAuthentication no' in main.read_text()
    assert 'DenyUsers root' in Path(state['policy']).read_text()
    assert 'DenyUsers ubuntu' in Path(state['policy']).read_text()
    ns['commit'](state)
    assert json.loads((Path(state['directory'])/'state.json').read_text())['phase']=='committed'
    assert ['systemctl','stop','test-recovery.timer'] in calls


def test_timer_failure_never_changes_ssh(tmp_path,monkeypatch):
    root,ns,calls=load_helpers(tmp_path,monkeypatch)
    state=applied_state(root,ns);main=Path(state['main']);before=main.read_text()
    def command(args,**kwargs):
        if args[0]=='systemd-run':raise RuntimeError('timer unavailable')
        return ''
    ns['command']=command
    with pytest.raises(RuntimeError,match='timer unavailable'):ns['apply'](state)
    assert main.read_text()==before and state['phase']=='prepared'


def test_rollback_script_restores_only_our_changes_and_retains_outside_edits(tmp_path,monkeypatch):
    root,ns,calls=load_helpers(tmp_path,monkeypatch)
    state=applied_state(root,ns);main=Path(state['main']);original=main.read_text()
    ns['apply'](state)
    main.write_text(main.read_text()+'# outside edit\n')
    monkeypatch.setattr(sys,'argv',['rollback.py',state['directory']])
    script=ns['ROLLBACK'].replace('import fcntl,json,os,subprocess,sys,tempfile,time','import fcntl,json,os,sys,tempfile,time')
    exec(compile(script,'<isolated recovery>','exec'),{'subprocess':ns['subprocess']})
    assert main.read_text()==original+'# outside edit\n'
    assert json.loads((Path(state['directory'])/'state.json').read_text())['phase']=='rolled-back'


def test_remote_scripts_compile():
    compile(REMOTE_SCRIPT,'<remote helper>','exec')
    compile(WRAPPER,'<sudo wrapper>','exec')


@pytest.mark.asyncio
async def test_add_tabs_switch_and_options_are_not_in_existing_payload(tmp_path,monkeypatch):
    import curses
    from test_ui import Window
    from ssh_manager.controller import SSHManager,Form
    from ssh_manager.console import Console
    monkeypatch.setattr(curses,'has_colors',lambda:False)
    manager=SSHManager(tmp_path/'config',tmp_path/'data',demo=True)
    ui=Console(manager);ui.win=Window()
    form=Form('Add Connection',[('alias','Alias','test',False)],tabs=True,secure_fields=[('sudo','Sudo','passwordless',False),('password','Password','secret',True)],choices={'sudo':['passwordless','password required']})
    task=asyncio.create_task(ui.show(form));await asyncio.sleep(0)
    assert ui.focus==-1 and not form.secure_tab
    ui.modal_key(curses.KEY_RIGHT);assert form.secure_tab
    ui.draw()
    assert any('Add Existing Connection' in text for _,_,text,_ in ui.win.writes)
    assert any('Add new Server and Secure' in text for _,_,text,_ in ui.win.writes)
    assert not any('secret' in text for _,_,text,_ in ui.win.writes)
    ui.focus=1;ui.modal_key(curses.KEY_RIGHT)
    assert ui.values[1]=='password required'
    ui.focus=-1;ui.modal_key(curses.KEY_LEFT)
    assert not form.secure_tab
    ui.focus=1;ui.modal_key('\n')
    result=await task
    assert result==dict(alias='test',_secure=False)
    assert ui.values==[]


def test_managed_policy_parses_with_real_openssh(tmp_path,monkeypatch):
    import shutil,subprocess
    binary=shutil.which('sshd') or '/usr/sbin/sshd'
    if not Path(binary).is_file():pytest.skip('No local sshd parser installed')
    root,ns,calls=load_helpers(tmp_path,monkeypatch)
    state=applied_state(root,ns)
    ns['apply'](state)
    key=root/'host-key'
    subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
    check=subprocess.run([binary,'-t','-f',state['main'],'-h',str(key)],capture_output=True,text=True)
    assert check.returncode==0,check.stderr
    args=[binary,'-T','-f',state['main'],'-h',str(key),'-C','user=newadmin,host=127.0.0.1,addr=127.0.0.1,laddr=192.0.2.1,lport=22']
    result=subprocess.run(args,capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    assert 'passwordauthentication no' in result.stdout
    assert 'authenticationmethods publickey' in result.stdout
    assert 'allowtcpforwarding no' not in result.stdout
    root_result=subprocess.run([*args[:-1],'user=root,host=127.0.0.1,addr=127.0.0.1,laddr=192.0.2.1,lport=22'],capture_output=True,text=True)
    assert 'permitrootlogin no' in root_result.stdout
    assert 'denyusers root' in root_result.stdout


def test_disabling_optional_restrictions_does_not_force_key_only_or_root_deny(tmp_path,monkeypatch):
    root,ns,calls=load_helpers(tmp_path,monkeypatch)
    state=applied_state(root,ns)
    state.update(lock_root=False,block_bootstrap=False,key_only=False)
    ns['apply'](state)
    policy=Path(state['policy']).read_text();main=Path(state['main']).read_text()
    assert 'PermitRootLogin no' not in policy and 'DenyUsers' not in policy
    assert 'AuthenticationMethods publickey' not in main
    assert 'PasswordAuthentication no' not in main
    assert 'AllowTcpForwarding no' not in main


def test_setup_mode_can_be_selected_and_saved_with_password_sudo(tmp_path,monkeypatch):
    # Verify option transport itself: no forced passwordless default is hidden
    # behind the form choice or setup object.
    plan=Setup('newadmin','/key','ssh-ed25519 AAAA','a'*24,passwordless=False,lock_root=False,block_bootstrap=False,key_only=False)
    payload=plan.payload('prepare','ubuntu')
    assert payload['passwordless'] is False and payload['lock_root'] is False
    assert 'security_updates' not in payload and 'disable_forwarding' not in payload


def test_general_admin_uses_unlocked_vault_sudo_password_without_argv_secret(monkeypatch,tmp_path):
    from ssh_manager.remote import Remote
    recorded=[]
    def run(args,**kwargs):
        recorded.append((args,kwargs))
        return SimpleNamespace(returncode=0,stdout='{"users":[]}',stderr='')
    monkeypatch.setattr('ssh_manager.remote.subprocess.run',run)
    host=Host('test',tmp_path/'config',0,1,['test'],'',hostname='localhost',user='newadmin')
    remote=Remote(SSHConfig(tmp_path/'config'),lambda host:'private-sudo-password')
    assert remote.run(host,'inspect')=={'users':[]}
    args,kwargs=recorded[0]
    assert 'private-sudo-password' not in ' '.join(args)
    assert json.loads(kwargs['input'])['_sudo_password']=='private-sudo-password'


@pytest.mark.asyncio
async def test_generate_new_key_is_saved_discovered_and_selected_for_setup(tmp_path,monkeypatch):
    import subprocess
    from contextlib import nullcontext
    from ssh_manager.controller import SSHManager
    manager=SSHManager(tmp_path/'config',tmp_path/'data')
    manager.vault.unlock('test master password for new keys')
    captured={}
    class UI:
        async def show(self,form):
            return dict(alias='new-server',hostname='localhost',port='22',user='root',identity='',_secure=True,login_password='',new_user='newadmin',new_identity='new',new_password='',sudo_mode='passwordless',lock_root='yes',block_bootstrap='yes',key_only='yes')
        def suspend(self):return nullcontext()
    manager.ui=UI()
    def generate(path,label):
        path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
        subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-C',label,'-f',str(path)],check=True)
    monkeypatch.setattr('ssh_manager.controller.create_key',generate)
    async def secure(alias,plan):captured.update(alias=alias,plan=plan)
    monkeypatch.setattr(manager,'secure_connection',secure)
    await manager.connection_form()
    key=Path(captured['plan'].keypath)
    assert key.parent==tmp_path/'keys'
    assert key.is_file() and Path(str(key)+'.pub').is_file()
    assert captured['plan'].public_key==Path(str(key)+'.pub').read_text().strip()
    assert any(row['path']==str(key)+'.pub' for row in manager.scan_keys())
    assert captured['alias']=='new-server'


@pytest.mark.asyncio
async def test_enter_lists_available_private_keys_and_selects_one(tmp_path,monkeypatch):
    import curses
    from test_ui import Window
    from ssh_manager.controller import SSHManager,Form
    from ssh_manager.console import Console
    manager=SSHManager(tmp_path/'config',tmp_path/'data',demo=True)
    monkeypatch.setattr(manager,'default_key',lambda *args:'')
    private=tmp_path/'laptop'
    subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(private)],check=True)
    public=Path(str(private)+'.pub')
    public_only=tmp_path/'ipad.pub';public_only.write_text('public-only placeholder')
    monkeypatch.setattr(manager,'scan_keys',lambda:[dict(path=str(public),label='Laptop',fingerprint='SHA256:test'),dict(path=str(public_only),label='iPad',fingerprint='SHA256:other')])
    monkeypatch.setattr(curses,'has_colors',lambda:False)
    ui=Console(manager);ui.win=Window()
    form=Form('Keys',[('new_identity','Key Path','',False),('password','Password','',True)],key_pickers={'new_identity'})
    task=asyncio.create_task(ui.show(form));await asyncio.sleep(0)
    ui.modal_key('\n')
    for _ in range(50):
        if not ui.key_picker['loading']:break
        await asyncio.sleep(.01)
    assert [row[1] for row in ui.key_picker['rows']]==['','new',str(private),':import-key:']
    ui.draw()
    ui.modal_key(curses.KEY_END);ui.modal_key(curses.KEY_UP);ui.modal_key('\n')
    assert ui.key_picker is None and ui.values[0]==str(private) and ui.focus==1
    ui.focus=0;ui.values[0]='new';ui.modal_key('\n')
    while ui.key_picker['loading']:await asyncio.sleep(.01)
    ui.modal_key('\n')
    assert ui.key_picker is None and ui.focus==1
    ui.modal_key('\x1b');await task


class PortTransport(Transport):
    def __init__(self,fail_verify=0):
        super().__init__()
        self.plan.new_port=2222
        self.fail_verify=fail_verify
        self.finalized=False
    def use_port(self,port):self.calls.append(('use-port',port))
    def run(self,op):
        if op=='finish-port':
            self.calls.append(op);self.finalized=True
            return dict(phase='port-finalized')
        if op=='verify':
            if self.verifications+1==self.fail_verify:
                self.calls.append(op);raise RuntimeError('new-port login unavailable')
            result=super().run(op)
            if self.finalized:result['phase']='port-finalized'
            return result
        return super().run(op)


@pytest.mark.asyncio
async def test_new_port_handover_checks_both_stages_before_saving():
    transport=PortTransport()
    async def save():transport.calls.append('save-config')
    result=await provision(transport,save,lambda *x:None,lambda x:None)
    assert transport.calls==['prepare','verify','apply',('use-port',2222),'verify','finish-port','verify','save-config','commit']
    assert result['phase']=='committed'


@pytest.mark.asyncio
@pytest.mark.parametrize('verification',[2,3])
async def test_new_port_connection_failure_rolls_back_before_commit(verification):
    transport=PortTransport(fail_verify=verification)
    async def save():pytest.fail('Unverified port must not be saved')
    with pytest.raises(RuntimeError,match='unavailable'):
        await provision(transport,save,lambda *x:None,lambda x:None)
    assert transport.calls[-1]=='rollback' and 'commit' not in transport.calls
    if verification==2:assert 'finish-port' not in transport.calls


def test_transport_new_port_uses_pinned_host_identity_and_recovery_falls_back(tmp_path,monkeypatch):
    plan=Setup('newadmin','/key','ssh-ed25519 AAAA','a'*24,new_port=2222)
    host=Host('test',tmp_path/'config',0,1,['test'],'',hostname='example.com',port=22,user='root')
    transport=SecureTransport(SSHConfig(tmp_path/'config'),host,plan)
    transport.use_port(2222)
    args=transport.arguments(True)
    assert args[args.index('-p')+1]=='2222'
    assert 'HostKeyAlias=example.com' in args
    calls=[]
    def run(op,port):
        calls.append((op,port))
        if port==2222:raise RuntimeError('blocked by firewall')
        return dict(phase='rolled-back')
    monkeypatch.setattr(transport,'_run',run)
    assert transport.run('rollback')['phase']=='rolled-back'
    assert calls==[('rollback',2222),('rollback',22)]


def port_state(root,ns,socket_mode=False):
    main=root/'ssh'/'sshd_config'
    include=root/'ssh'/'conf.d';include.mkdir()
    (include/'ports.conf').write_text('Port 22\n# keep included comment\n')
    main.write_text('Port 22\nInclude '+str(include/'*.conf')+'\nPasswordAuthentication yes\n')
    state=applied_state(root,ns)
    documents=ns['config_documents']()
    details=dict(new_port=2222,old_port=22,socket_unit='',socket_listeners=[],documents=documents)
    ns['backup_ports'](state,details)
    if socket_mode:
        state.update(socket_unit='ssh.socket',socket_listeners=[('[::]',22)],socket_override=str(root/'units'/'zz-managed.conf'))
    original_effective=ns['effective']
    def effective(user,conn):
        value=original_effective(user,conn)
        value['port']='2222' if state['phase']=='port-finalized' else '22 2222'
        return value
    ns['effective']=effective
    return state


def test_port_include_edits_and_finalization_are_reversible(tmp_path,monkeypatch):
    root,ns,calls=load_helpers(tmp_path,monkeypatch)
    state=port_state(root,ns)
    main=Path(state['main']);before=main.read_text()
    included=root/'ssh'/'conf.d'/'ports.conf';before_include=included.read_text()
    ns['apply'](state)
    assert 'Port 22\n' in Path(state['policy']).read_text()
    assert 'Port 2222\n' in Path(state['policy']).read_text()
    assert '# ssh-manager-port-' in included.read_text()
    with pytest.raises(ValueError,match='fresh new-port'):
        ns['finish_port'](state)
    with pytest.raises(ValueError,match='finalized'):
        ns['commit'](state)
    state['new_port_verified']=True
    ns['p']['_connection']='127.0.0.1 1234 192.0.2.1 2222'
    ns['finish_port'](state)
    assert 'Port 22\n' not in Path(state['policy']).read_text()
    assert 'Port 2222\n' in Path(state['policy']).read_text()
    included.write_text(included.read_text()+'# outside edit\n')
    monkeypatch.setattr(sys,'argv',['rollback.py',state['directory']])
    script=ns['ROLLBACK'].replace('import fcntl,json,os,subprocess,sys,tempfile,time','import fcntl,json,os,sys,tempfile,time')
    exec(compile(script,'<isolated port recovery>','exec'),{'subprocess':ns['subprocess']})
    assert main.read_text()==before
    assert included.read_text()==before_include+'# outside edit\n'
    assert json.loads((Path(state['directory'])/'state.json').read_text())['phase']=='rolled-back'


def test_socket_handover_keeps_old_listener_until_new_login_is_proven(tmp_path,monkeypatch):
    root,ns,calls=load_helpers(tmp_path,monkeypatch)
    state=port_state(root,ns,socket_mode=True)
    def command(args,**kwargs):
        calls.append(args)
        if '--property=Listen' in args:
            lines=Path(state['socket_override']).read_text().splitlines()
            return ' '.join(line.split('=',1)[1]+' (Stream)' for line in lines if line.startswith('ListenStream=') and line!='ListenStream=')
        return ''
    ns['command']=command
    ns['apply'](state)
    override=Path(state['socket_override'])
    assert 'ListenStream=[::]:22\n' in override.read_text()
    assert 'ListenStream=[::]:2222\n' in override.read_text()
    assert ['systemctl','daemon-reload'] in calls
    assert ['systemctl','restart','ssh.socket','ssh.service'] in calls
    state['new_port_verified']=True;ns['p']['_connection']='127.0.0.1 1234 192.0.2.1 2222'
    ns['finish_port'](state)
    assert 'ListenStream=[::]:22\n' not in override.read_text()
    assert 'ListenStream=[::]:2222\n' in override.read_text()
    monkeypatch.setattr(sys,'argv',['rollback.py',state['directory']])
    script=ns['ROLLBACK'].replace('import fcntl,json,os,subprocess,sys,tempfile,time','import fcntl,json,os,sys,tempfile,time')
    exec(compile(script,'<isolated socket recovery>','exec'),{'subprocess':ns['subprocess']})
    assert not override.exists()
    assert json.loads((Path(state['directory'])/'state.json').read_text())['phase']=='rolled-back'


def test_socket_unsafe_service_is_rejected_before_changes(tmp_path,monkeypatch):
    root,ns,calls=load_helpers(tmp_path,monkeypatch)
    ns['p']=dict(new_port=2222,bootstrap_user='root')
    ns['command']=lambda args,**kwargs:'control-group'
    with pytest.raises(ValueError,match='KillMode=process'):
        ns['plan_ports']('127.0.0.1 1234 192.0.2.1 22','ssh.service')
    assert not (root/'state').exists()


@pytest.mark.parametrize('port',[0,-1,65536,'2222',True])
def test_remote_rejects_invalid_port_before_other_commands(tmp_path,monkeypatch,port):
    root,ns,calls=load_helpers(tmp_path,monkeypatch)
    ns['p']=dict(new_port=port)
    with pytest.raises(ValueError,match='Invalid new SSH port'):
        ns['plan_ports']('127.0.0.1 1234 192.0.2.1 22','ssh.service')
    assert not calls


def test_two_port_and_final_port_config_with_real_sshd_parser(tmp_path,monkeypatch):
    import shutil,subprocess
    binary=shutil.which('sshd') or '/usr/sbin/sshd'
    if not Path(binary).is_file():pytest.skip('No sshd parser installed')
    root,ns,calls=load_helpers(tmp_path,monkeypatch)
    state=port_state(root,ns)
    ns['apply'](state)
    key=root/'host-key'
    subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
    def ports():
        result=subprocess.run([binary,'-T','-f',state['main'],'-h',str(key)],capture_output=True,text=True)
        assert result.returncode==0,result.stderr
        return {line.split()[1] for line in result.stdout.splitlines() if line.startswith('port ')}
    assert ports()=={'22','2222'}
    state['new_port_verified']=True;ns['p']['_connection']='127.0.0.1 1234 192.0.2.1 2222'
    ns['finish_port'](state)
    assert ports()=={'2222'}


def test_new_port_and_host_key_alias_saved_in_ssh_config(tmp_path):
    config=SSHConfig(tmp_path/'config')
    config.save(dict(alias='server',hostname='example.com',port='2222',user='newadmin',identity='/key',hostkeyalias='example.com'))
    host=config.discover()[0]
    assert host.port==2222 and host.host_key_alias=='example.com'
    assert 'hostkeyalias "example.com"' in (tmp_path/'config').read_text()


@pytest.mark.asyncio
async def test_keep_current_account_hides_only_new_details_and_preserves_security_options(tmp_path,monkeypatch):
    import curses
    from test_ui import Window
    from ssh_manager.controller import SSHManager
    from ssh_manager.console import Console
    manager=SSHManager(tmp_path/'config',tmp_path/'data',demo=True)
    captured=[]
    class Capture:
        async def show(self,form):captured.append(form)
    manager.ui=Capture();await manager.connection_form()
    form=captured[0]
    ui=Console(manager);ui.win=Window(44,110)
    monkeypatch.setattr(curses,'has_colors',lambda:False)
    task=asyncio.create_task(ui.show(form));await asyncio.sleep(0)
    ui.modal_key(curses.KEY_RIGHT)
    fields=ui.form_fields();index={field[0]:i for i,field in enumerate(fields)}
    ui.values[index['user']]='root'
    ui.values[index['new_user']]='remembered-user'
    ui.values[index['new_password']]='hidden-password-must-not-submit'
    ui.values[index['new_port']]='2222'
    ui.focus=index['block_bootstrap'];ui.modal_key(curses.KEY_RIGHT)
    fields=ui.form_fields();keys=[field[0] for field in fields]
    assert all(key not in keys for key in ('new_user','new_identity','new_password','sudo_mode','lock_root'))
    assert 'key_only' in keys and 'new_port' in keys
    assert ui.values[keys.index('new_port')]=='2222'
    ui.draw()
    visible='\n'.join(text for _,_,text,_ in ui.win.writes)
    assert 'Current Password' in visible
    assert 'New Secure Account' not in visible and 'Security Settings' in visible
    ui.focus=keys.index('block_bootstrap');ui.modal_key(curses.KEY_LEFT)
    fields=ui.form_fields();keys=[field[0] for field in fields]
    assert ui.values[keys.index('new_user')]=='remembered-user'
    ui.focus=keys.index('block_bootstrap');ui.modal_key(curses.KEY_RIGHT)
    fields=ui.form_fields();ui.focus=len(fields);ui.modal_key('\n')
    result=await task
    assert result['_secure'] and result['block_bootstrap']=='no' and result['new_port']=='2222'
    assert 'new_password' not in result and 'new_user' not in result
    assert 'hidden-password-must-not-submit' not in str(result)


@pytest.mark.asyncio
async def test_keep_current_account_plan_applies_security_without_creating_user(tmp_path,monkeypatch):
    import subprocess
    from ssh_manager.controller import SSHManager
    manager=SSHManager(tmp_path/'config',tmp_path/'data')
    manager.vault.unlock('test password for current account mode')
    key=tmp_path/'current-key'
    subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
    class UI:
        async def show(self,form):
            return dict(alias='current',hostname='localhost',port='22',user='root',identity=str(key),_secure=True,block_bootstrap='no',login_password='existing-short-password',key_only='yes',new_port='2222',new_user='ignored-hidden-name',new_identity='new')
    manager.ui=UI();captured={}
    async def secure(alias,plan):captured.update(alias=alias,plan=plan)
    monkeypatch.setattr(manager,'secure_connection',secure)
    monkeypatch.setattr('ssh_manager.controller.create_key',lambda *args:pytest.fail('No new-user key should be generated'))
    await manager.connection_form()
    plan=captured['plan']
    assert plan.reuse_existing and plan.new_user=='root' and plan.new_port==2222
    assert not plan.block_bootstrap and not plan.lock_root
    assert plan.key_only and plan.keypath==str(key)
    assert plan.recovery_password=='existing-short-password'


def test_prepare_current_account_keeps_password_groups_and_sudo_policy(tmp_path,monkeypatch):
    root,ns,calls=load_helpers(tmp_path,monkeypatch)
    plan=Setup('root','/key','ssh-ed25519 AAAA','existing-password',reuse_existing=True,lock_root=False,block_bootstrap=False)
    ns['p']={**plan.payload('prepare','root'),'_connection':'127.0.0.1 1234 192.0.2.1 22'}
    ns['pwd']=SimpleNamespace(getpwnam=lambda user:SimpleNamespace(pw_name='root',pw_gid=0))
    ns['grp']=SimpleNamespace(getgrnam=lambda user:pytest.fail('Existing groups must be retained'))
    ns['shutil']=SimpleNamespace(which=lambda name:'/fake/'+name)
    ns['change_key']=lambda user,key:calls.append(['authorise',user])
    sudoers=root/'sudoers.d';sudoers.mkdir()
    rule=sudoers/'99-ssh-manager-root';rule.write_text('# existing policy\n')
    before=(root/'ssh'/'sshd_config').read_text()
    assert ns['prepare']()['phase']=='prepared'
    assert not any(args[0] in ('useradd','userdel','usermod','chpasswd','visudo') for args in calls)
    assert rule.read_text()=='# existing policy\n'
    assert (root/'ssh'/'sshd_config').read_text()==before
    assert ['authorise','root'] in calls


def test_retained_root_cannot_be_disabled(tmp_path,monkeypatch):
    root,ns,calls=load_helpers(tmp_path,monkeypatch)
    plan=Setup('root','/key','ssh-ed25519 AAAA','',reuse_existing=True,lock_root=True,block_bootstrap=False)
    ns['p']={**plan.payload('prepare','root'),'_connection':'127.0.0.1 1234 192.0.2.1 22'}
    ns['pwd']=SimpleNamespace(getpwnam=lambda user:SimpleNamespace(pw_name='root',pw_gid=0))
    with pytest.raises(ValueError,match='Cannot disable the root'):
        ns['prepare']()
    assert not calls and not (root/'state').exists()


def test_current_root_verification_does_not_require_sudo_group_membership(tmp_path,monkeypatch):
    root,ns,calls=load_helpers(tmp_path,monkeypatch)
    state=applied_state(root,ns)
    state.update(new_user='root',bootstrap_user='root',reuse_existing=True,lock_root=False,block_bootstrap=False)
    ns['p']={'_actual_user':'root'}
    ns['pwd']=SimpleNamespace(getpwnam=lambda user:SimpleNamespace(pw_name='root',pw_gid=0))
    ns['grp']=SimpleNamespace(getgrnam=lambda group:pytest.fail('Root does not require sudo membership'))
    assert ns['verify'](state)==dict(phase='prepared',login='root',sudo=True)


def test_retained_root_key_only_policy_with_real_sshd_parser(tmp_path,monkeypatch):
    import shutil,subprocess
    binary=shutil.which('sshd') or '/usr/sbin/sshd'
    if not Path(binary).is_file():pytest.skip('No sshd parser installed')
    root,ns,calls=load_helpers(tmp_path,monkeypatch)
    state=applied_state(root,ns)
    state.update(new_user='root',bootstrap_user='root',reuse_existing=True,lock_root=False,block_bootstrap=False)
    ns['p']={'_actual_user':'root'}
    ns['apply'](state)
    key=root/'host-key'
    subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
    result=subprocess.run([binary,'-T','-f',state['main'],'-h',str(key),'-C','user=root,host=127.0.0.1,addr=127.0.0.1,laddr=192.0.2.1,lport=22'],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    assert 'permitrootlogin no' not in result.stdout and 'denyusers root' not in result.stdout
    assert 'passwordauthentication no' in result.stdout and 'authenticationmethods publickey' in result.stdout


def test_generated_password_uses_six_lowercase_alphanumeric_dash_six(monkeypatch):
    from ssh_manager.secure import generate_account_password
    sequence=iter('a1b2c3d4e5f6')
    def choice(alphabet):
        assert alphabet=='abcdefghijklmnopqrstuvwxyz0123456789'
        return next(sequence)
    monkeypatch.setattr('ssh_manager.secure.secrets.choice',choice)
    assert generate_account_password()=='a1b2c3-d4e5f6'


def test_remote_accepts_requested_generated_password_format(tmp_path,monkeypatch):
    root,ns,calls=load_helpers(tmp_path,monkeypatch)
    plan=Setup('newadmin','/key','ssh-ed25519 AAAA','abc123-def456')
    ns['p']={**plan.payload('prepare','root'),'_connection':'127.0.0.1 1234 192.0.2.1 22'}
    lookups=iter([None,SimpleNamespace(pw_uid=1001)])
    def getuser(name):
        user=next(lookups)
        if user is None:raise KeyError(name)
        return user
    ns['pwd']=SimpleNamespace(getpwnam=getuser)
    ns['grp']=SimpleNamespace(getgrnam=lambda name:SimpleNamespace(gr_gid=42))
    ns['shutil']=SimpleNamespace(which=lambda name:'/fake/'+name)
    ns['change_key']=lambda user,key:None
    inputs=[]
    def command(args,**kwargs):
        if args[0]=='chpasswd':inputs.append(kwargs['input'])
        return ''
    ns['command']=command
    assert ns['prepare']()['phase']=='prepared'
    assert inputs==['newadmin:abc123-def456\n']
    assert 'abc123-def456' not in (root/'state'/plan.setup_id/'state.json').read_text()


@pytest.mark.asyncio
async def test_account_password_link_is_encrypted_and_survives_inspection(tmp_path,monkeypatch):
    from ssh_manager.controller import SSHManager
    from ssh_manager.secure import generate_account_password
    manager=SSHManager(tmp_path/'config',tmp_path/'data',demo=True)
    host=Host('test',tmp_path/'config',0,1,['test'],'',hostname='localhost',user='newadmin')
    manager.hosts=[host];manager.selected_alias='test';manager.store.reconcile([host])
    manager.vault.unlock('master password for account record test')
    password=generate_account_password()
    ident=manager.store.get('test')['id']
    manager.vault.put(ident,'newadmin',password)
    manager.store.record_account_password('test','newadmin')
    account=manager.store.get('test')['users'][0]
    assert account['password_ref']==f'{ident}:newadmin'
    assert manager.vault.records[account['password_ref']]['password']==password
    assert password.encode() not in (tmp_path/'data'/'inventory.sqlite3').read_bytes()
    assert password not in manager.vault.path.read_text()
    monkeypatch.setattr(manager.remote,'run',lambda *a,**kw:dict(users=[dict(user='newadmin',uid=1000,home='/home/newadmin',shell='/bin/bash',keys=[])],domains=[],interface_public_ips=[],hostname='server'))
    await manager.inspect_host(host)
    refreshed=manager.store.get('test')['users'][0]
    assert refreshed['uid']==1000 and refreshed['password_ref']==account['password_ref']
    manager.view='users';manager.render_table()
    assert all(password not in str(row) for row in manager.rows)


def test_bootstrap_accepts_only_new_host_keys_and_followup_requires_known_key(tmp_path):
    plan=Setup('newadmin','/private/key','ssh-ed25519 AAAA','a'*20)
    host=Host('test',tmp_path/'config',0,1,['test'],'',hostname='localhost',user='admin')
    transport=SecureTransport(SSHConfig(tmp_path/'config'),host,plan)
    initial=transport.arguments(False)
    assert 'StrictHostKeyChecking=accept-new' in initial
    assert 'StrictHostKeyChecking=no' not in initial
    transport.use_port(2200)
    verified=transport.arguments(True)
    assert 'StrictHostKeyChecking=yes' in verified
    assert 'HostKeyAlias=localhost' in verified


def test_bootstrap_key_is_used_through_temporary_owner_only_copy(tmp_path,monkeypatch):
    source=tmp_path/'download.pem';source.write_text('private-key-test-data');source.chmod(0o644)
    plan=Setup('newadmin','/managed/key','ssh-ed25519 AAAA','recovery',bootstrap_key=str(source))
    host=Host('test',tmp_path/'config',0,1,['test'],'',hostname='localhost',user='root')
    paths=[]
    def run(args,**kwargs):
        path=Path(args[args.index('-i')+1]);paths.append(path)
        assert path!=source and path.read_bytes()==source.read_bytes()
        assert path.stat().st_mode & 0o777==0o600
        return SimpleNamespace(returncode=0,stdout='{"phase":"prepared"}',stderr='')
    monkeypatch.setattr('ssh_manager.secure.subprocess.run',run)
    SecureTransport(SSHConfig(tmp_path/'config'),host,plan).run('prepare')
    assert source.exists() and source.stat().st_mode & 0o777==0o644
    assert not paths[0].exists()


@pytest.mark.asyncio
async def test_new_port_requires_separate_red_firewall_confirmation(tmp_path,monkeypatch):
    from ssh_manager.controller import SSHManager
    manager=SSHManager(tmp_path/'config',tmp_path/'data')
    host=Host('test',tmp_path/'config',0,1,['test'],'',hostname='localhost',user='admin')
    monkeypatch.setattr(manager.config,'discover',lambda:[host])
    seen=[]
    class UI:
        async def show(self,form):
            seen.append(form)
            return {} if len(seen)==1 else None
    manager.ui=UI()
    await manager.secure_connection('test',Setup('newadmin','/key','ssh-ed25519 AAAA','password',new_port=2200))
    assert len(seen)==3 and seen[0].title=='Review new server setup'
    assert seen[2].title=='Review new server setup'
    warning=seen[1]
    assert warning.text_colour==2 and warning.default_cancel
    assert warning.help_text=='YOU ARE CHANGING THE SSH PORT ON THIS SERVER. PLEASE CONFIRM THE NEW PORT IS ALLOWED THROUGH THE FIREWALL'
    assert not manager.vault.path.exists()


@pytest.mark.asyncio
async def test_secure_bootstrap_key_not_persisted_as_connection_identity(tmp_path,monkeypatch):
    from ssh_manager.controller import SSHManager
    from ssh_manager.remote import create_key
    config=tmp_path/'ssh'/'config'
    manager=SSHManager(config,tmp_path/'data')
    bootstrap=tmp_path/'Downloads'/'bootstrap'
    managed=tmp_path/'ssh'/'id_ed25519_managed'
    create_key(bootstrap,'temporary','');create_key(managed,'managed','')
    class UI:
        async def show(self,form):
            return dict(alias='test',hostname='localhost',port='22',user='admin',identity=str(bootstrap),_secure=True,login_password='',block_bootstrap='yes',new_user='newadmin',new_identity=str(managed),new_password='',sudo_mode='passwordless',key_only='yes',new_port='')
    manager.ui=UI()
    plans=[]
    async def secure(alias,plan):plans.append(plan)
    monkeypatch.setattr(manager,'secure_connection',secure)
    await manager.connection_form()
    assert plans[0].bootstrap_key==str(bootstrap) and plans[0].keypath==str(managed)
    assert str(bootstrap) not in config.read_text()
    assert str(managed) in config.read_text()


@pytest.mark.asyncio
async def test_cancel_secure_overview_returns_to_filled_connection_form(tmp_path):
    from ssh_manager.controller import SSHManager
    from ssh_manager.console import Console
    from ssh_manager.remote import create_key
    from test_vault_workflow import settled
    current=tmp_path/'current';managed=tmp_path/'managed'
    create_key(current,'current','');create_key(managed,'managed','')
    manager=SSHManager(tmp_path/'config',tmp_path/'data');ui=Console(manager)
    task=asyncio.create_task(manager.connection_form())
    await settled(lambda:ui.modal is not None)
    ui.dismiss(dict(alias='keep-details',hostname='localhost',port='22',user='admin',identity=str(current),_secure=True,login_password='',block_bootstrap='yes',new_user='newadmin',new_identity=str(managed),new_password='',sudo_mode='passwordless',key_only='yes',new_port='2200'))
    await settled(lambda:ui.modal is not None and ui.modal.title=='Review new server setup')
    assert 'keep-details' not in manager.table_ids
    ui.modal_key('\x1b')
    await settled(lambda:ui.modal is not None and ui.modal.title=='Add Connection')
    values={f[0]:value for f,value in zip(ui.form_fields(),ui.values)}
    assert values['alias']=='keep-details' and values['new_user']=='newadmin'
    assert values['identity']==str(current) and values['new_identity']==str(managed)
    assert values['new_port']=='2200'
    assert 'Host keep-details' not in manager.config.path.read_text()
    ui.modal_key('\x1b');await task


@pytest.mark.asyncio
@pytest.mark.parametrize('generated',[True,False])
async def test_review_only_shows_generated_password_and_highlights_firewall(tmp_path,monkeypatch,generated):
    from ssh_manager.controller import SSHManager
    manager=SSHManager(tmp_path/'config',tmp_path/'data')
    host=Host('test',tmp_path/'config',0,1,['test'],'',hostname='localhost',user='admin')
    monkeypatch.setattr(manager.config,'discover',lambda:[host])
    seen=[]
    class UI:
        async def show(self,form):seen.append(form);return None
    manager.ui=UI()
    await manager.secure_connection('test',Setup('newadmin','/key','ssh-ed25519 AAAA','abcdef-123456',new_port=2200,generated_password=generated))
    assert ('Generated password: abcdef-123456' in seen[0].help_text)==generated
    assert seen[0].highlights['Allow the new port in your VM/provider firewall before continuing.']==2
    assert 'abcdef-123456' not in repr(manager.store.events())


def test_default_key_uses_first_verified_matching_pair(tmp_path,monkeypatch):
    from ssh_manager.controller import SSHManager
    from ssh_manager.remote import create_key
    manager=SSHManager(tmp_path/'config',tmp_path/'data')
    manager.config.path.write_text('')
    bad=tmp_path/'missing';valid=tmp_path/'id_ed25519_actual'
    create_key(valid,'actual','')
    def resolve(probe):
        probe.identities=[str(bad),str(valid)];return probe
    monkeypatch.setattr(manager.config,'resolve',resolve)
    assert manager.default_key('server')==str(valid)
    valid.with_suffix('.pub').unlink()
    assert manager.default_key('server')==''


@pytest.mark.asyncio
async def test_new_account_field_prefills_resolved_key_path(tmp_path,monkeypatch):
    from ssh_manager.controller import SSHManager
    manager=SSHManager(tmp_path/'config',tmp_path/'data')
    actual=str(tmp_path/'id_ed25519_actual')
    monkeypatch.setattr(manager,'default_key',lambda *args:actual)
    class UI:
        async def show(self,form):
            assert next(f[2] for f in form.secure_fields if f[0]=='new_identity')==actual
            return None
    manager.ui=UI();await manager.connection_form()


@pytest.mark.asyncio
async def test_reconnect_countdown_expires_then_requests_rollback(monkeypatch):
    monkeypatch.setattr('ssh_manager.secure.RECONNECT_WINDOW_SECONDS',.03)
    transport=Transport();original=transport.run;updates=[]
    def run(op):
        if op=='verify' and transport.verifications==1:
            transport.calls.append(op);raise RuntimeError('Cannot reconnect')
        return original(op)
    transport.run=run
    async def save():pytest.fail('Must not save an unverified connection')
    with pytest.raises(RuntimeError):
        await provision(transport,save,lambda *args:None,lambda message:None,lambda error,seconds:updates.append((error,seconds)))
    assert any('Cannot reconnect' in error and seconds>0 for error,seconds in updates)
    assert updates[-1][1]==0 and transport.calls[-1]=='rollback'


@pytest.mark.asyncio
async def test_reconnect_success_clears_error_and_cancels_countdown(monkeypatch):
    monkeypatch.setattr('ssh_manager.secure.RECONNECT_WINDOW_SECONDS',3)
    transport=Transport();original=transport.run;updates=[];failed=False
    def run(op):
        nonlocal failed
        if op=='verify' and transport.verifications==1 and not failed:
            failed=True;transport.calls.append(op);raise RuntimeError('Temporary failure')
        return original(op)
    transport.run=run
    async def save():pass
    result=await provision(transport,save,lambda *args:None,lambda message:None,lambda error,seconds:updates.append((error,seconds)))
    assert result['phase']=='committed' and 'rollback' not in transport.calls
    assert any(error=='Temporary failure' for error,_ in updates)
    assert updates[-1]==('',None)


@pytest.mark.parametrize('new_port',[None,2200])
def test_retry_after_rollback_resumes_only_its_previously_created_account(tmp_path,monkeypatch,new_port):
    root,ns,calls=load_helpers(tmp_path,monkeypatch)
    ns['plan_ports']=lambda *args:dict(new_port=ns['p'].get('new_port'),old_port=22,socket_unit='',socket_listeners=[],documents=[]) if ns['p'].get('new_port') else {}
    users={}
    def getuser(name):
        if name not in users:raise KeyError(name)
        return users[name]
    ns['pwd']=SimpleNamespace(getpwnam=getuser)
    ns['grp']=SimpleNamespace(getgrnam=lambda name:SimpleNamespace(gr_gid=42))
    ns['shutil']=SimpleNamespace(which=lambda name:'/fake/'+name)
    authorized=root/'authorized_keys'
    ns['keyfile']=lambda name:(users[name],str(root),str(authorized))
    ns['change_key']=lambda name,key:authorized.write_text(key+'\n')
    def command(args,**kwargs):
        calls.append(args)
        if args[0]=='useradd':users[args[-1]]=SimpleNamespace(pw_uid=1001)
        return ''
    ns['command']=command
    first=Setup('newadmin','/key','ssh-ed25519 AAAA','abc123-def456',new_port=2222)
    ns['p']={**first.payload('prepare','admin'),'_connection':'127.0.0.1 1234 192.0.2.1 22'}
    ns['prepare']()
    state=json.loads((root/'state'/first.setup_id/'state.json').read_text())
    state['phase']='rolled-back';ns['save'](state)
    # Even if a failed retry recorded a newer ID before prepare succeeded,
    # root-owned records identify the prior account by its actual key and user.
    retry=Setup('newadmin','/key','ssh-ed25519 AAAA','abc123-def456',new_port=new_port,resume_setup_id='e'*32)
    ns['p']={**retry.payload('prepare','admin'),'_connection':'127.0.0.1 1234 192.0.2.1 22'}
    assert ns['prepare']()['phase']=='prepared'
    assert sum(args[0]=='useradd' for args in calls)==1
    assert json.loads((root/'state'/retry.setup_id/'state.json').read_text())['created_uid']==1001
    # An unrelated key cannot adopt the account.
    mismatch=Setup('newadmin','/other','ssh-ed25519 BBBB','abc123-def456',resume_setup_id=first.setup_id)
    ns['p']={**mismatch.payload('prepare','admin'),'_connection':'127.0.0.1 1234 192.0.2.1 22'}
    with pytest.raises(ValueError,match='no matching recoverable setup'):
        ns['prepare']()


def test_retry_does_not_resume_while_ssh_recovery_is_pending(tmp_path,monkeypatch):
    root,ns,calls=load_helpers(tmp_path,monkeypatch)
    folder=root/'state'/('a'*32);folder.mkdir(parents=True)
    (folder/'key.pub').write_text('ssh-ed25519 AAAA\n')
    (folder/'state.json').write_text(json.dumps(dict(new_user='newadmin',bootstrap_user='admin',phase='applied',created_uid=1001)))
    ns['pwd']=SimpleNamespace(getpwnam=lambda name:SimpleNamespace(pw_uid=1001))
    ns['p']={'resume_setup_id':'a'*32,'bootstrap_user':'admin'}
    with pytest.raises(ValueError,match='Recovery is still pending'):
        ns['resumable_account']('newadmin','ssh-ed25519 AAAA')
