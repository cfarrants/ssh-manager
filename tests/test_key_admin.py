import asyncio
import pytest
import curses
from ssh_manager.controller import SSHManager, KeyAdmin, Form
from ssh_manager.console import Console
from test_ui import Window
from test_vault_workflow import settled


def manager(tmp_path):
    config=tmp_path/'config';config.write_text('Host one\n HostName localhost\n User admin\n')
    app=SSHManager(config,tmp_path/'data')
    app.hosts=app.config.discover();app.store.reconcile(app.hosts)
    app.selected_alias='one';app.render_table(selected='one')
    return app


@pytest.mark.asyncio
@pytest.mark.parametrize('action',['revoke','cycle'])
async def test_missing_private_pair_warns_before_mutation(tmp_path,monkeypatch,action):
    app=manager(tmp_path);key=dict(fingerprint='SHA256:foreign',public_key='ssh-ed25519 AAAA',line='ssh-ed25519 AAAA other-device')
    calls=[]
    def remote(host,op,**kwargs):
        calls.append(op);assert op=='inspect-keys'
        return dict(user='admin',keys=[key])
    monkeypatch.setattr(app.remote,'run',remote)
    monkeypatch.setattr(app,'scan_keys',lambda:[])
    seen=[]
    class UI:
        async def show(self,screen):
            seen.append(screen)
            if isinstance(screen,KeyAdmin):
                await settled(lambda:not screen.loading)
                if sum(isinstance(s,KeyAdmin) for s in seen)>1:return None
                assert screen.keys[0]['local_private']=='' and screen.keys[0]['label']=='other-device'
                return action,screen.keys[0]
            assert isinstance(screen,Form) and screen.default_cancel
            assert 'No matching private key' in screen.help_text
            assert screen.text_colour==2 or 2 in screen.highlights.values()
            return None
    app.ui=UI();await app.action_operations.__wrapped__(app)
    assert all(op=='inspect-keys' for op in calls)
    assert sum(isinstance(s,Form) for s in seen)==1


@pytest.mark.asyncio
async def test_revoke_selected_server_key_and_refresh(tmp_path,monkeypatch):
    app=manager(tmp_path);keys=[dict(fingerprint='SHA256:foreign',public_key='ssh-ed25519 AAAA',line='ssh-ed25519 AAAA other-device')]
    revoked=[]
    def remote(host,op,**kwargs):
        if op=='inspect-keys':return dict(user='admin',keys=list(keys))
        assert op=='revoke-key';revoked.append(kwargs);keys.clear();return 'Key revoked'
    monkeypatch.setattr(app.remote,'run',remote);monkeypatch.setattr(app,'scan_keys',lambda:[])
    panels=[]
    class UI:
        async def show(self,screen):
            if isinstance(screen,KeyAdmin):
                await settled(lambda:not screen.loading);panels.append(screen)
                return ('revoke',screen.keys[0]) if len(panels)==1 else None
            assert screen.title=='Revoke SSH Key';return {}
    app.ui=UI();await app.action_operations.__wrapped__(app)
    assert revoked==[dict(user='admin',key='ssh-ed25519 AAAA')]
    assert panels[1].keys==[]


@pytest.mark.asyncio
async def test_key_admin_keyboard_actions_and_rendering(tmp_path,monkeypatch):
    app=manager(tmp_path);ui=Console(app);ui.win=Window()
    monkeypatch.setattr(curses,'has_colors',lambda:False)
    key=dict(label='Other laptop',fingerprint='SHA256:foreign',public_key='ssh-ed25519 AAAA',local_private='')
    panel=KeyAdmin('admin@one',keys=[key],loading=False)
    task=asyncio.create_task(ui.show(panel));await settled(lambda:ui.modal is panel)
    ui.draw();text='\n'.join(t for _,_,t,_ in ui.win.writes)
    assert 'Key Admin' in text and 'Other laptop' in text and 'NO LOCAL PRIVATE KEY' in text
    ui.modal_key('c');assert await task==('cycle',key)


@pytest.mark.asyncio
async def test_cycle_selected_key_without_local_private_replaces_only_that_key(tmp_path,monkeypatch):
    from ssh_manager.remote import create_key,local_keys
    app=manager(tmp_path);host=app.hosts[0]
    foreign=tmp_path/'remote'/'foreign';create_key(foreign,'other-device','')
    remote_key=local_keys(foreign.parent)[0]
    foreign.unlink()  # Simulates a public key whose private half is on another device.
    selected=dict(public_key=remote_key['public_key'],fingerprint=remote_key['fingerprint'],label='other-device',local_private='')
    replacement=tmp_path/'replacement';revoked=[]
    async def details(defer=False):return dict(path=str(replacement),label='replacement',passphrase='')
    monkeypatch.setattr(app,'new_key_dialog',details)
    def run(host,op,**kwargs):
        if op=='revoke-key':revoked.append(kwargs['key'])
        return 'Done'
    monkeypatch.setattr(app.remote,'run',run)
    monkeypatch.setattr(app.remote,'verify_key',lambda *args:True)
    async def inspect(host):pass
    def refresh(**kwargs):
        future=asyncio.get_running_loop().create_future();future.set_result(None);return future
    monkeypatch.setattr(app,'inspect_host',inspect);monkeypatch.setattr(app,'refresh_inventory',refresh)
    class UI:
        async def show(self,screen):return {} if isinstance(screen,Form) else None
    app.ui=UI();await app.rotate_key_wizard(host,current_key=selected)
    assert revoked==[remote_key['public_key']]
    assert replacement.exists() and not foreign.exists()
