import asyncio
from pathlib import Path
import curses
import pytest
from ssh_manager.controller import SSHManager, ADD_KEY, VIEWS
from ssh_manager.console import Console
from ssh_manager.config import Host
from test_ui import Window
from test_vault_workflow import settled, submit


def setup(tmp_path):
    app=SSHManager(tmp_path/'config',tmp_path/'data')
    app.hosts=[Host('one',tmp_path/'config',0,1,['one'],'',hostname='192.0.2.1',user='admin',identities=[str(tmp_path/'device')])]
    app.store.reconcile(app.hosts);app.selected_alias='one'
    app.key_rows=[dict(path=str(tmp_path/'device.pub'),fingerprint='SHA256:example',label='Laptop',public_key='ssh-ed25519 AAAA')]
    app.store.update('one',users=[dict(user='chris',keys=[dict(fingerprint='SHA256:example')])])
    app.vault.open_automatic();app.vault.put(app.store.get('one')['id'],'chris','private-password')
    app.view='accounts';app.render_table()
    return app


def test_combined_inventory_and_expanded_details(tmp_path,monkeypatch):
    app=setup(tmp_path)
    assert VIEWS==('connections','accounts','activity')
    assert not any(key==":add-account:" for key in app.table_ids)
    key=app.key_rows[0]['path']
    assert app.account_rows[key]['deployments']==['admin@one (SSH config)','chris@one (observed)']
    assert 'private-password' not in repr(app.rows)
    ui=Console(app);ui.win=Window();monkeypatch.setattr(curses,'has_colors',lambda:False)
    app.select(app.table_ids.index(key));ui.handle_key(curses.KEY_RIGHT)
    assert key in app.expanded_keys and app.view=='accounts'
    ui.draw();rendered='\n'.join(t for _,_,t,_ in ui.win.writes)
    assert all(t in rendered for t in ('SSH Keys','User Accounts','SHA256:example','admin@one','chris@one','Generate New Key'))
    assert 'private-password' not in rendered
    ui.handle_key(' ');assert not app.expanded_keys
    ui.win=Window(18,60);ui.draw()
    for _ in range(len(app.rows)):ui.handle_key(curses.KEY_DOWN)
    assert app.row_id()==key


@pytest.mark.asyncio
async def test_password_popup_is_compact_and_cleared(tmp_path,monkeypatch):
    app=setup(tmp_path);ui=Console(app);ui.win=Window()
    monkeypatch.setattr(curses,'has_colors',lambda:False)
    row=next(k for k,v in app.account_rows.items() if v.get('user')=='chris')
    app.select(app.table_ids.index(row))
    task=asyncio.create_task(app.action_open.__wrapped__(app))
    await settled(lambda:ui.modal is not None)
    modal=ui.modal
    assert modal.compact and modal.secret and modal.value=='private-password'
    ui.draw();ui.modal_key('\x1b');await task
    assert modal.value=='' and ui.modal is None
    assert 'private-password' not in repr(app.store.events())


def test_accounts_selection_does_not_change_connection_selection(tmp_path):
    app=setup(tmp_path)
    app.hosts.append(Host('two',tmp_path/'config',0,1,['two'],'',hostname='192.0.2.2',user='other'))
    app.store.reconcile(app.hosts)
    app.render_table()
    row=next(k for k,v in app.account_rows.items() if v.get('alias')=='two')
    app.select(app.table_ids.index(row))
    assert app.selected_alias=='one'
    assert app.require_host().alias=='two'
    app.view='connections';app.render_table()
    assert app.row_id()=='one'


@pytest.mark.asyncio
async def test_key_actions_choose_server_explicitly(tmp_path):
    app=setup(tmp_path);ui=Console(app)
    app.select(app.table_ids.index(app.key_rows[0]['path']))
    task=asyncio.create_task(app.choose_action_host())
    await settled(lambda:ui.modal is not None)
    assert ui.modal.title=='Choose server'
    ui.modal_key('\x1b')
    assert await task is None


def test_activity_has_no_selected_connection_context(tmp_path,monkeypatch):
    app=setup(tmp_path);app.view='activity';app.render_table()
    ui=Console(app);ui.win=Window()
    monkeypatch.setattr(curses,'has_colors',lambda:False)
    ui.draw()
    rendered='\n'.join(t for _,_,t,_ in ui.win.writes)
    assert 'Config:' not in rendered and 'Identities:' not in rendered
    assert 'admin@192.0.2.1' not in rendered


def test_in_app_passphrase_encrypts_key_and_stays_off_command_line(tmp_path,monkeypatch):
    import subprocess
    from ssh_manager.remote import create_key
    original=subprocess.run
    captured=[]
    def run(args,**kwargs):
        captured.append((args,kwargs));return original(args,**kwargs)
    monkeypatch.setattr('ssh_manager.remote.subprocess.run',run)
    path=tmp_path/'encrypted-key'
    create_key(path,'Test device','example-passphrase')
    args,kwargs=captured[0]
    assert 'example-passphrase' not in repr(args)
    assert kwargs['input']=='example-passphrase\nexample-passphrase\n'
    assert original(['ssh-keygen','-y','-P','','-f',str(path)],capture_output=True).returncode!=0
    unlocked=original(['ssh-keygen','-y','-f',str(path)],input='example-passphrase\n',capture_output=True,text=True,start_new_session=True)
    assert unlocked.returncode==0 and unlocked.stdout.split()[:2]==path.with_suffix('.pub').read_text().split()[:2]
    with pytest.raises(ValueError,match='already exists'):
        create_key(path,'Test device','replacement')


@pytest.mark.asyncio
async def test_key_form_masks_and_clears_passphrase(tmp_path,monkeypatch):
    app=setup(tmp_path);ui=Console(app);ui.win=Window()
    monkeypatch.setattr(curses,'has_colors',lambda:False)
    calls=[]
    monkeypatch.setattr('ssh_manager.controller.create_key',lambda *args:calls.append(args))
    monkeypatch.setattr(app,'scan_keys',lambda:app.key_rows)
    task=asyncio.create_task(app.action_new_key.__wrapped__(app))
    await settled(lambda:ui.modal is not None)
    assert next(f for f in ui.modal.fields if f[0]=='passphrase')[3] is True
    submit(ui,[str(tmp_path/'new-key'),'Laptop','hidden-passphrase'])
    await task
    assert calls==[(str(tmp_path/'new-key'),'Laptop','hidden-passphrase')]
    assert ui.modal is None and not ui.values and not ui._field_values
    assert 'hidden-passphrase' not in repr(app.store.events())


@pytest.mark.asyncio
async def test_new_key_filename_default_and_inline_validation(tmp_path,monkeypatch):
    app=setup(tmp_path);ui=Console(app);calls=[]
    monkeypatch.setattr('ssh_manager.controller.create_key',lambda *args:calls.append(args))
    monkeypatch.setattr(app,'scan_keys',lambda:app.key_rows)
    task=asyncio.create_task(app.action_new_key.__wrapped__(app))
    await settled(lambda:ui.modal is not None)
    modal=ui.modal
    assert ui.values[0]=='id_ed25519_' and ui.focus==0 and ui.caret==len('id_ed25519_')
    for filename in ('','id_ed25519_'):
        submit(ui,[filename,'Comment','secret'])
        await settled(lambda:not modal.submitting)
        assert 'Enter a name' in modal.error and ui.modal is modal and not calls
    existing=tmp_path/'id_ed25519_used.pub';existing.write_text('untouched')
    submit(ui,['id_ed25519_used','Comment','secret'])
    await settled(lambda:not modal.submitting)
    assert 'already exists' in modal.error and not calls
    assert existing.read_text()=='untouched'
    submit(ui,['id_ed25519_laptop','Comment','secret'])
    await task
    assert calls==[(str(tmp_path/'id_ed25519_laptop'),'Comment','secret')]


@pytest.mark.asyncio
async def test_delete_connection_defaults_to_cancel_and_requires_delete_selection(tmp_path,monkeypatch):
    app=setup(tmp_path);ui=Console(app);calls=[]
    monkeypatch.setattr(app.config,'remove',lambda host:calls.append(host.alias))
    monkeypatch.setattr(app,'refresh_inventory',lambda **kwargs:None)
    task=asyncio.create_task(app.delete_connection(app.hosts[0]))
    await settled(lambda:ui.modal is not None)
    assert ui.modal.fields==[] and ui.modal.submit=='Delete' and ui.modal.cancel=='Cancel'
    assert ui.focus==1
    ui.modal_key('\n');await task
    assert not calls
    task=asyncio.create_task(app.delete_connection(app.hosts[0]))
    await settled(lambda:ui.modal is not None)
    ui.modal_key(curses.KEY_LEFT);ui.modal_key('\n');await task
    assert calls==['one']


@pytest.mark.asyncio
async def test_key_delete_blocks_attached_server_then_allows_after_removal(tmp_path,monkeypatch):
    from ssh_manager.remote import create_key
    from ssh_manager.key_deletion import remove_key_files
    private=tmp_path/'device'
    create_key(private,'device','')
    app=setup(tmp_path);ui=Console(app)
    # Use the real key inventory so deletion also checks its fingerprint.
    app.key_rows=app.scan_keys();item=next(k for k in app.key_rows if k['path']==str(private)+'.pub')
    current=list(app.hosts)
    monkeypatch.setattr(app.config,'discover',lambda:list(current))
    task=asyncio.create_task(app.delete_local_key(item))
    await settled(lambda:ui.modal is not None)
    assert ui.modal.title=='Key cannot be deleted' and 'one' in ui.modal.value
    assert private.exists()
    ui.modal_key('\x1b');await task
    current.clear()
    task=asyncio.create_task(app.delete_local_key(item))
    await settled(lambda:ui.modal is not None)
    assert ui.modal.title=='Delete SSH key' and ui.focus==1
    ui.modal_key('\n');await task
    assert private.exists()  # Cancel is the default.
    task=asyncio.create_task(app.delete_local_key(item))
    await settled(lambda:ui.modal is not None)
    ui.modal_key(curses.KEY_LEFT);ui.modal_key('\n');await task
    assert not private.exists() and not private.with_suffix('.pub').exists()
    assert list((app.store.directory/'deleted-keys').glob('*/device'))
    assert not any(k['path']==item['path'] for k in app.key_rows)


@pytest.mark.asyncio
async def test_key_delete_rechecks_attachments_at_confirmation(tmp_path,monkeypatch):
    from ssh_manager.remote import create_key
    private=tmp_path/'device';create_key(private,'device','')
    app=setup(tmp_path);ui=Console(app)
    hosts=list(app.hosts);current=[]
    monkeypatch.setattr(app.config,'discover',lambda:list(current))
    item=next(k for k in app.scan_keys() if k['path']==str(private)+'.pub')
    task=asyncio.create_task(app.delete_local_key(item))
    await settled(lambda:ui.modal is not None)
    modal=ui.modal
    current.extend(hosts)
    ui.modal_key(curses.KEY_LEFT);ui.modal_key('\n')
    await settled(lambda:not modal.submitting)
    assert ui.modal is modal and 'attached server' in modal.error and private.exists()
    ui.modal_key('\x1b');await task


def test_secure_progress_displays_error_and_rollback_countdown(tmp_path,monkeypatch):
    app=setup(tmp_path);ui=Console(app);ui.win=Window()
    monkeypatch.setattr(curses,'has_colors',lambda:False)
    app.busy=app.secure_setup_running=True
    app.setup_error='Cannot reconnect to the new SSH port'
    app.setup_countdown=17
    ui.draw()
    text='\n'.join(t for _,_,t,_ in ui.win.writes)
    assert 'Cannot reconnect' in text and 'Rollback in 17s' in text


def test_secure_connections_remain_hidden_until_completed(tmp_path):
    app=setup(tmp_path);app.view='connections'
    # Ordinary SSH-config connections are visible without a login verification.
    app.render_table();assert 'one' in app.table_ids
    app.pending_secure.add('one')
    app.render_table();assert 'one' not in app.table_ids
    app.pending_secure.clear()
    for status in ('pending','running','stopped'):
        app.store.update('one',secure_setup={'status':status})
        app.render_table();assert 'one' not in app.table_ids
    app.store.update('one',secure_setup={'status':'complete'})
    app.render_table();assert 'one' in app.table_ids
