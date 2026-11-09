import pytest
import asyncio
import curses
from ssh_manager.controller import Form, Viewer, ProgressComplete
from ssh_manager.console import Console
from test_accounts import setup
from test_ui import Window


@pytest.mark.asyncio
@pytest.mark.parametrize('key_only',[False,True])
async def test_authorise_key_policy_and_verified_order(tmp_path,monkeypatch,key_only):
    app=setup(tmp_path);host=app.hosts[0];calls=[];screens=[]
    monkeypatch.setattr(app,'default_key',lambda *args:'/chosen/key')
    monkeypatch.setattr(app,'read_public_key',lambda path:'ssh-ed25519 AAAA')
    monkeypatch.setattr(app.remote,'verify_key',lambda *args:calls.append('verify-key'))
    monkeypatch.setattr(app.config,'save',lambda values,host:calls.append('save-config'))
    def refresh(**kwargs):
        future=asyncio.get_running_loop().create_future();future.set_result(None);return future
    monkeypatch.setattr(app,'refresh_inventory',refresh)
    class Transport:
        def __init__(self,config,host,plan):
            self.plan=plan;self.phase='prepared'
            assert plan.reuse_existing and plan.new_user==host.user
            assert not plan.block_bootstrap and not plan.lock_root
            assert plan.key_only==key_only
        def authorise_key(self):calls.append('authorise')
        def run(self,op):
            calls.append(op)
            if op=='apply':self.phase='applied'
            if op=='verify':return dict(login=host.user,sudo=True,phase=self.phase)
            return dict(phase='committed' if op=='commit' else self.phase)
    monkeypatch.setattr('ssh_manager.secure.SecureTransport',Transport)
    class UI:
        async def show(self,screen):
            screens.append(screen)
            if isinstance(screen,Form):
                return {'identity':'/chosen/key'} if screen.title=='Authorise SSH Key' else {'key_only':'yes' if key_only else 'no'}
            assert isinstance(screen,ProgressComplete) and screen.title=='SSH key authorised'
            assert 'SSH key authorised' in app.setup_completed and any('Fresh key login' in action for action in app.setup_completed)
    app.ui=UI()
    await app.authorise_ssh_key(host)
    assert calls==(['prepare','verify','apply','verify','save-config','commit'] if key_only else ['authorise','verify-key','save-config'])
    assert screens[1].title=='Disable password SSH logins?'
    assert any(u['user']==host.user and u['keys'] for u in app.store.get(host.alias)['users'])
    assert not app.busy


def test_authorise_progress_shows_accumulated_actions(tmp_path,monkeypatch):
    app=setup(tmp_path);ui=Console(app);ui.win=Window()
    monkeypatch.setattr(curses,'has_colors',lambda:False)
    app.busy=app.key_setup_running=True
    app.setup_completed=['Connected as admin','SSH key authorised','Fresh key login verified']
    app.setup_stage=3;app.setup_stages=4
    app.say('Updating connection…')
    ui.draw()
    text='\n'.join(t for _,_,t,_ in ui.win.writes)
    assert 'Authorise SSH Key' in text and 'Stage 3/4' in text
    assert all(action in text for action in app.setup_completed)


@pytest.mark.asyncio
async def test_rotation_wizard_creates_installs_verifies_then_revokes(tmp_path,monkeypatch):
    from ssh_manager.controller import SSHManager, Viewer
    from ssh_manager.remote import create_key
    old=tmp_path/'old';newpath=tmp_path/'new'
    create_key(old,'old','')
    config=tmp_path/'config';config.write_text(f'Host one\n HostName localhost\n User admin\n IdentityFile {old}\n')
    app=SSHManager(config,tmp_path/'data');app.hosts=app.config.discover();app.store.reconcile(app.hosts)
    host=app.hosts[0];calls=[]
    monkeypatch.setattr(app,'default_key',lambda *args:str(old))
    async def generate(defer=False):
        assert defer and not newpath.exists()
        return dict(path=str(newpath),passphrase='',label='new')
    def create(path,label,passphrase):
        calls.append('create');create_key(path,label,passphrase)
    monkeypatch.setattr('ssh_manager.controller.create_key',create)
    monkeypatch.setattr(app,'new_key_dialog',generate)
    def remote(host,op,**kwargs):
        calls.append(op)
        if op=='inspect-keys':
            from ssh_manager.remote import local_keys
            return dict(user=host.user,keys=[dict(fingerprint=local_keys(tmp_path,[str(old)])[0]['fingerprint'])])
        if op=='revoke-key':assert app.config.discover()[0].identities[0]==str(newpath)
        return 'Done'
    monkeypatch.setattr(app.remote,'run',remote)
    monkeypatch.setattr(app.remote,'verify_key',lambda *args:calls.append('verify'))
    async def inspect(host):pass
    def refresh(**kwargs):
        future=asyncio.get_running_loop().create_future();future.set_result(None);return future
    monkeypatch.setattr(app,'inspect_host',inspect);monkeypatch.setattr(app,'refresh_inventory',refresh)
    class UI:
        async def show(self,screen):
            if screen.title=='Rotate Key · current key':return dict(identity=str(old))
            if screen.title=='Rotate Key · review':return {}
            assert isinstance(screen,ProgressComplete) and screen.title=='SSH key rotated'
            assert any('Old public key revoked' in action for action in app.setup_completed)
    app.ui=UI();await app.rotate_key_wizard(host)
    assert calls==['inspect-keys','create','add-key','verify','revoke-key']
    assert old.exists() and old.with_suffix('.pub').exists()


def test_key_passphrase_bridge_answers_only_the_selected_key_prompt(tmp_path):
    import subprocess,sys,os
    from ssh_manager.secure import askpass
    path=str(tmp_path/'new-key')
    with askpass('test-key-passphrase',path,kind='key') as env:
        rejected=subprocess.run([sys.executable,'-m','ssh_manager.askpass','Enter passphrase for /another/key:'],env=env,capture_output=True,text=True,timeout=5)
        assert rejected.returncode!=0 and not rejected.stdout
        accepted=subprocess.run([sys.executable,'-m','ssh_manager.askpass','Enter passphrase for '+path+':'],env=env,capture_output=True,text=True,timeout=5)
        assert accepted.returncode==0 and accepted.stdout.strip()=='test-key-passphrase'
        assert all('test-key-passphrase' not in value for value in env.values())


@pytest.mark.asyncio
async def test_cancel_rotation_review_does_not_create_replacement(tmp_path,monkeypatch):
    from ssh_manager.controller import SSHManager
    from ssh_manager.remote import create_key
    old=tmp_path/'old';create_key(old,'old','')
    config=tmp_path/'config';config.write_text(f'Host one\n HostName localhost\n User admin\n IdentityFile {old}\n')
    app=SSHManager(config,tmp_path/'data');app.hosts=app.config.discover();app.store.reconcile(app.hosts)
    monkeypatch.setattr(app,'default_key',lambda *args:str(old))
    from ssh_manager.remote import local_keys
    fingerprint=local_keys(tmp_path,[str(old)])[0]['fingerprint']
    monkeypatch.setattr(app.remote,'run',lambda *args,**kwargs:dict(user='admin',keys=[dict(fingerprint=fingerprint)]))
    def unexpected(*args,**kwargs):pytest.fail('Key creation must wait for Rotate confirmation')
    monkeypatch.setattr('ssh_manager.controller.create_key',unexpected)
    def refresh(**kwargs):
        future=asyncio.get_running_loop().create_future();future.set_result(None);return future
    monkeypatch.setattr(app,'refresh_inventory',refresh)
    target=tmp_path/'not-created'/'id_ed25519_test'
    class UI:
        async def show(self,screen):
            if screen.title=='Rotate Key · current key':return dict(identity=str(old))
            if screen.title=='Replacement key details':
                values=dict(path=str(target),label='Test',passphrase='example-passphrase')
                assert screen.submit=='Continue'
                await screen.submit_handler(values)
                return values
            assert screen.title=='Rotate Key · review'
            assert not target.exists() and not target.parent.exists()
            return None
    app.ui=UI();await app.rotate_key_wizard(app.hosts[0])
    assert not target.exists() and not target.with_name(target.name+'.pub').exists()
    assert old.exists() and not any(e['action']=='Key created' for e in app.store.events())


@pytest.mark.asyncio
async def test_current_key_read_only_ignores_typing_and_key_picker(tmp_path):
    from ssh_manager.controller import Form
    from test_vault_workflow import settled
    app=setup(tmp_path);ui=Console(app)
    form=Form('Current Key',[('identity','Current SSH Key','/verified/key',False)],read_only={'identity'},key_pickers={'identity'})
    task=asyncio.create_task(ui.show(form));await settled(lambda:ui.modal is form)
    for key in ('x','\x7f',curses.KEY_LEFT,' '):ui.modal_key(key)
    assert ui.values==['/verified/key']
    ui.modal_key('\n');assert ui.key_picker is None and ui.focus==1
    ui.modal_key('\x1b');await task


@pytest.mark.asyncio
async def test_authorise_key_selection_opens_list_without_text_form(tmp_path,monkeypatch):
    from ssh_manager.controller import Form
    from ssh_manager.remote import create_key
    from test_vault_workflow import settled
    key=tmp_path/'device';create_key(key,'device','')
    app=setup(tmp_path);ui=Console(app);ui.win=Window()
    monkeypatch.setattr(app,'default_key',lambda *args:'')
    monkeypatch.setattr(curses,'has_colors',lambda:False)
    form=Form('Authorise SSH Key',[('identity','SSH Key','',False)],key_pickers={'identity'},key_list_only=True)
    task=asyncio.create_task(ui.show(form))
    await settled(lambda:ui.key_picker is not None and not ui.key_picker['loading'])
    assert ui.key_picker['rows'][-1][0]=='Add SSH Key'
    ui.draw()
    assert any('Available SSH Keys' in t for _,_,t,_ in ui.win.writes)
    assert not any(t=='Authorise SSH Key' for _,_,t,_ in ui.win.writes)
    ui.key_picker['focus']=next(i for i,r in enumerate(ui.key_picker['rows']) if r[1]==str(key))
    ui.modal_key('\n')
    assert await task=={'identity':str(key)}


@pytest.mark.asyncio
async def test_completed_progress_retains_actions_and_adds_close_button(tmp_path,monkeypatch):
    from test_vault_workflow import settled
    app=setup(tmp_path);ui=Console(app);ui.win=Window()
    monkeypatch.setattr(curses,'has_colors',lambda:False)
    app.busy=app.key_setup_running=True
    app.setup_title='Rotate SSH Key';app.setup_completed=['Key created','Key verified','Old key removed']
    app.setup_stage=app.setup_stages=5
    ui.draw()
    title_before=next((row,col) for row,col,t,_ in ui.win.writes if t=='Rotate SSH Key')
    ui.win.writes.clear()
    task=asyncio.create_task(ui.show(ProgressComplete('SSH key rotated')))
    await settled(lambda:isinstance(ui.modal,ProgressComplete))
    ui.draw()
    assert next((row,col) for row,col,t,_ in ui.win.writes if t=='Rotate SSH Key')==title_before
    text='\n'.join(t for _,_,t,_ in ui.win.writes)
    assert all(action in text for action in app.setup_completed)
    assert 'Complete' in text and 'Close' in text
    ui.modal_key('\n');await task
