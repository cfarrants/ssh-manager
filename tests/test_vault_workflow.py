import asyncio
from contextlib import nullcontext
from pathlib import Path
import pytest
from ssh_manager.console import Console
from ssh_manager.controller import SSHManager
from ssh_manager.store import Vault


async def settled(predicate,timeout=5):
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(.01)


def submit(ui,values):
    ui.form_fields()
    ui.values=list(values)
    ui.focus=len(ui.form_fields())
    ui.modal_key('\n')


@pytest.mark.asyncio
async def test_new_vault_opens_automatically_without_popup(tmp_path):
    app=SSHManager(tmp_path/'config',tmp_path/'data')
    ui=Console(app)
    assert await app.action_unlock.__wrapped__(app) is True
    assert app.vault.cipher and app.vault.path.exists() and ui.modal is None
    assert app.vault.protection=='keyring'
    app.vault.records['test']={'password':'example-secret'}
    app.vault.save()
    assert 'example-secret' not in app.vault.path.read_text()
    app.vault.lock()
    app.vault.open_automatic()
    assert app.vault.records['test']['password']=='example-secret'


@pytest.mark.asyncio
async def test_wrong_existing_master_password_keeps_dialog_open(tmp_path):
    app=SSHManager(tmp_path/'config',tmp_path/'data')
    app.vault.unlock('the correct master password');app.vault.lock()
    before=app.vault.path.read_bytes()
    ui=Console(app)
    task=asyncio.create_task(app.action_unlock.__wrapped__(app))
    await settled(lambda:ui.modal is not None)
    assert ui.modal.title=='Convert existing vault · once only' and len(ui.modal.fields)==1
    modal=ui.modal
    submit(ui,['the wrong master password'])
    await settled(lambda:not modal.submitting)
    assert 'Incorrect master password' in modal.error
    assert ui.modal is modal and not task.done()
    assert app.vault.path.read_bytes()==before
    submit(ui,['the correct master password'])
    assert await task is True
    assert app.vault.protection=='keyring'
    backup=next(app.vault.path.parent.glob('vault.pre-keyring-backup-*.json'))
    assert backup.read_bytes()!=before
    restored=Vault(tmp_path);restored.path=backup;restored.open_automatic()
    assert restored.records==app.vault.records
    app.vault.lock();app.vault.open_automatic()


@pytest.mark.asyncio
async def test_cancel_vault_returns_to_filled_secure_add_form(tmp_path):
    app=SSHManager(tmp_path/'config',tmp_path/'data')
    app.vault.unlock('existing master password');app.vault.lock()
    ui=Console(app)
    task=asyncio.create_task(app.connection_form())
    await settled(lambda:ui.modal is not None)
    original=ui.modal
    result=dict(alias='debian-test',hostname='192.0.2.25',port='22',user='admin',identity='/chosen/key',_secure=True,login_password='',block_bootstrap='yes',new_user='newadmin',new_identity='new',new_password='',sudo_mode='passwordless',key_only='yes',new_port='')
    ui.dismiss(result)
    await settled(lambda:ui.modal is not None and ui.modal is not original)
    assert ui.modal.title=='Convert existing vault · once only'
    vault_modal=ui.modal
    ui.modal_key('\x1b')
    await settled(lambda:ui.modal is not None and ui.modal is not vault_modal)
    assert ui.modal.tabs and ui.modal.secure_tab
    ui.form_fields()
    values={field[0]:value for field,value in zip(ui.form_fields(),ui.values)}
    assert values['alias']=='debian-test' and values['hostname']=='192.0.2.25'
    assert values['new_user']=='newadmin' and values['new_identity']=='new'
    assert not app.config.path.exists() and app.vault.path.exists()
    ui.modal_key('\x1b');await task


@pytest.mark.asyncio
async def test_automatic_vault_resumes_secure_add_without_reentering_details(tmp_path,monkeypatch):
    app=SSHManager(tmp_path/'config',tmp_path/'data')
    ui=Console(app)
    called=[]
    def generate(path,label):
        path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
        import subprocess
        subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(path)],check=True)
    monkeypatch.setattr('ssh_manager.controller.create_key',generate)
    monkeypatch.setattr(ui,'suspend',nullcontext)
    async def secure(alias,plan):called.append((alias,plan.new_user))
    monkeypatch.setattr(app,'secure_connection',secure)
    task=asyncio.create_task(app.connection_form())
    await settled(lambda:ui.modal is not None)
    initial=ui.modal
    ui.dismiss(dict(alias='debian-test',hostname='localhost',port='22',user='admin',identity='',_secure=True,block_bootstrap='yes',login_password='',new_user='newadmin',new_identity='new',new_password='',sudo_mode='passwordless',key_only='yes',new_port=''))
    await task
    assert called==[('debian-test','newadmin')]
    assert app.vault.path.exists() and 'Host debian-test' in app.config.path.read_text()


def test_vault_creation_write_failure_does_not_leave_unpersisted_vault_unlocked(tmp_path,monkeypatch):
    vault=Vault(tmp_path)
    def fail():raise OSError('Cannot save vault')
    monkeypatch.setattr(vault,'save',fail)
    with pytest.raises(OSError,match='Cannot save'):
        vault.unlock('long enough master password')
    assert vault.cipher is None and vault.records=={} and not vault.path.exists()


@pytest.mark.asyncio
async def test_connection_validation_error_is_shown_in_same_form_with_values_retained(tmp_path):
    app=SSHManager(tmp_path/'config',tmp_path/'data')
    seen=[]
    class UI:
        async def show(self,form):
            seen.append(form)
            if len(seen)==1:
                return dict(alias='invalid alias',hostname='localhost',port='22',user='admin',identity='',_secure=False)
            assert form.tabs and form.error
            assert 'Alias' in form.error or 'alias' in form.error
            assert dict((f[0],f[2]) for f in form.fields)['alias']=='invalid alias'
            return dict(alias='valid-alias',hostname='localhost',port='22',user='admin',identity='',_secure=False)
    app.ui=UI()
    await app.connection_form()
    await app.jobs['config']
    assert len(seen)==2 and 'Host valid-alias' in app.config.path.read_text()


def test_wrong_os_key_preserves_file(tmp_path,monkeypatch):
    vault=Vault(tmp_path);vault.open_automatic()
    before=vault.path.read_bytes();vault.lock()
    from cryptography.fernet import Fernet
    monkeypatch.setattr('ssh_manager.store.get_key',lambda key_id:Fernet.generate_key())
    with pytest.raises(ValueError,match='not overwritten'):
        vault.open_automatic()
    assert vault.path.read_bytes()==before and vault.cipher is None


@pytest.mark.asyncio
async def test_automatic_open_failure_stays_in_retry_popup(tmp_path,monkeypatch):
    app=SSHManager(tmp_path/'config',tmp_path/'data');ui=Console(app)
    original=app.vault.open_automatic
    def fail():raise OSError('Cannot write saved-password file')
    monkeypatch.setattr(app.vault,'open_automatic',fail)
    task=asyncio.create_task(app.action_unlock.__wrapped__(app))
    await settled(lambda:ui.modal is not None)
    modal=ui.modal
    assert 'Cannot write' in modal.error
    submit(ui,[])
    await settled(lambda:not modal.submitting)
    assert ui.modal is modal and 'Cannot write' in modal.error and not task.done()
    monkeypatch.setattr(app.vault,'open_automatic',original)
    submit(ui,[])
    assert await task is True
    assert ui.modal is None and app.vault.cipher


@pytest.mark.asyncio
async def test_setup_overview_shows_all_settings_and_yes_no_without_text_confirmation(tmp_path,monkeypatch):
    import curses
    from test_ui import Window
    from ssh_manager.controller import Form
    app=SSHManager(tmp_path/'config',tmp_path/'data');ui=Console(app)
    ui.win=Window(24,100)
    monkeypatch.setattr(curses,'has_colors',lambda:False)
    text='\n'.join(['Server: admin@test:22','New administrator: chris','Sudo: passwordless','Current account SSH disabled: True','Key-only SSH: True','SSH port: 22 → 2200','Console accounts retained','Five-minute SSH rollback','Passwords saved in Vault','Allow new port in provider firewall'])
    task=asyncio.create_task(ui.show(Form('Review new server setup',[],text,'Yes',overview=True,cancel='No')))
    await settled(lambda:ui.modal is not None)
    ui.draw()
    rendered='\n'.join(item[2] for item in ui.win.writes)
    assert all(line in rendered for line in text.splitlines())
    assert 'Yes' in rendered and 'No' in rendered and 'Type SECURE' not in rendered
    ui.modal_key(curses.KEY_RIGHT);ui.modal_key('\n')
    assert await task is None
