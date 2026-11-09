import asyncio
import curses
from pathlib import Path
import subprocess
import pytest
from ssh_manager.controller import FileBrowser, IMPORT_KEY
from ssh_manager.console import Console
from ssh_manager.remote import create_key
from ssh_manager.key_import import import_key
from test_accounts import setup
from test_ui import Window
from test_vault_workflow import settled, submit


def test_import_encrypted_pair_and_no_overwrite(tmp_path):
    source=tmp_path/'source'/'device'
    create_key(source,'device-comment','test-passphrase')
    folder=tmp_path/'dest'
    with pytest.raises(ValueError,match='passphrase'):
        import_key(source,folder,'laptop','wrong')
    assert not folder.exists()
    public=Path(import_key(source,folder,'laptop','test-passphrase'))
    assert public.read_bytes()==source.with_suffix('.pub').read_bytes()
    assert (folder/'laptop').read_bytes()==source.read_bytes()
    assert (folder/'laptop').stat().st_mode & 0o777==0o600
    with pytest.raises(ValueError,match='already exists'):
        import_key(source,folder,'laptop','test-passphrase')
    assert source.exists()


def test_import_public_only_and_validate_file(tmp_path):
    source=tmp_path/'source'
    create_key(source,'public-comment','')
    with pytest.raises(ValueError,match='private key'):
        import_key(source.with_suffix('.pub'),tmp_path/'dest','public-only.pub')
    assert not (tmp_path/'dest').exists()
    invalid=tmp_path/'not-a-key';invalid.write_text('ordinary text')
    with pytest.raises(ValueError,match='private key'):
        import_key(invalid,tmp_path/'dest','invalid')
    with pytest.raises(ValueError,match='filename'):
        import_key(source,tmp_path/'dest','../outside')


@pytest.mark.asyncio
async def test_browser_starts_at_home_opens_hidden_folder_and_selects_file(tmp_path,monkeypatch):
    home=tmp_path/'home';ssh=home/'.ssh';ssh.mkdir(parents=True)
    key=ssh/'device';key.write_text('example')
    monkeypatch.setattr(Path,'home',classmethod(lambda cls:home))
    monkeypatch.setattr(curses,'has_colors',lambda:False)
    app=setup(tmp_path);ui=Console(app);ui.win=Window()
    task=asyncio.create_task(ui.show(FileBrowser()))
    await settled(lambda:ui.modal is not None and not ui.modal.loading)
    browser=ui.modal
    assert browser.directory==home
    assert not any(row[0]=='.ssh' for row in browser.visible_entries)
    ui.modal_key('.')
    ui.focus=next(i for i,row in enumerate(browser.visible_entries) if row[0]=='.ssh')
    ui.modal_key('\n');await settled(lambda:not browser.loading)
    assert browser.directory==ssh
    ui.draw()
    ui.focus=next(i for i,row in enumerate(browser.visible_entries) if row[0]=='device')
    ui.modal_key('\n')
    assert await task==str(key)
    task=asyncio.create_task(ui.show(FileBrowser()))
    await settled(lambda:ui.modal is not None and not ui.modal.loading)
    ui.modal_key('\x1b');assert await task is None


@pytest.mark.asyncio
async def test_import_workflow_invalid_file_stays_in_popup(tmp_path,monkeypatch):
    app=setup(tmp_path);ui=Console(app)
    monkeypatch.setattr(app,'scan_keys',lambda:app.key_rows)
    task=asyncio.create_task(app.action_import_key.__wrapped__(app))
    await settled(lambda:isinstance(ui.modal,FileBrowser))
    await settled(lambda:not ui.modal.loading)
    source=tmp_path/'invalid';source.write_text('not a key')
    ui.dismiss(str(source))
    await settled(lambda:ui.modal is not None and not isinstance(ui.modal,FileBrowser))
    modal=ui.modal
    submit(ui,['imported',''])
    await settled(lambda:not modal.submitting)
    assert ui.modal is modal and 'private key' in modal.error
    assert not (tmp_path/'imported.pub').exists()
    ui.modal_key('\x1b')
    await settled(lambda:isinstance(ui.modal,FileBrowser) and not ui.modal.loading)
    ui.modal_key('\x1b');await task
    app.render_table()
    assert IMPORT_KEY in app.table_ids


def test_matching_public_key_rejects_missing_or_mismatched_pair(tmp_path):
    from ssh_manager.key_import import matching_public_key
    one=tmp_path/'one';two=tmp_path/'two'
    create_key(one,'one','encrypted-passphrase')
    create_key(two,'two','')
    assert matching_public_key(one)
    public=one.with_suffix('.pub');original=public.read_bytes()
    public.unlink();assert not matching_public_key(one)
    public.write_bytes(two.with_suffix('.pub').read_bytes())
    assert not matching_public_key(one)
    public.write_bytes(original);assert matching_public_key(one)
    one.unlink();assert not matching_public_key(one)


@pytest.mark.asyncio
async def test_shared_browser_filters_names_extensions_and_hidden_toggle(tmp_path,monkeypatch):
    monkeypatch.setattr(curses,'has_colors',lambda:False)
    folder=tmp_path/'files';folder.mkdir()
    for name in ('Laptop.PEM','notes.txt','.secret.pem'):(folder/name).write_text('example')
    (folder/'.ssh').mkdir()
    app=setup(tmp_path);ui=Console(app);ui.win=Window()
    task=asyncio.create_task(ui.show(FileBrowser(directory=folder,title='Choose Any File')))
    await settled(lambda:ui.modal is not None and not ui.modal.loading)
    browser=ui.modal
    assert [r[0] for r in browser.visible_entries]==['..','Laptop.PEM','notes.txt']
    ui.draw()
    rendered=[t for _,_,t,_ in ui.win.writes]
    assert '..' in rendered and '[DIR] ..' not in rendered
    for c in 'pEm':ui.modal_key(c)
    assert [r[0] for r in browser.visible_entries]==['Laptop.PEM']
    ui.modal_key('\x1b');assert ui.modal is browser and not browser.filter_text
    ui.modal_key('.')
    assert '.secret.pem' in [r[0] for r in browser.visible_entries]
    ui.modal_key('.')
    assert '.secret.pem' not in [r[0] for r in browser.visible_entries]
    for c in 'notes.txt':ui.modal_key(c)
    assert [r[0] for r in browser.visible_entries]==['notes.txt']
    ui.modal_key('\x7f');assert browser.filter_text=='notes.tx'
    ui.modal_key('z');assert browser.visible_entries==[]
    ui.modal_key('\n');assert ui.modal is browser  # No selection when there are no matches.
    ui.modal_key('\x1b');ui.modal_key('\x1b');assert await task is None


@pytest.mark.asyncio
@pytest.mark.parametrize('secure',[False,True])
async def test_connection_key_picker_import_returns_to_filled_form(tmp_path,secure):
    from ssh_manager.controller import Form
    source=tmp_path/'source'/'device'
    create_key(source,'import-test','')
    app=setup(tmp_path);ui=Console(app)
    form=Form('Add Connection',[('alias','Alias','keep-this-alias',False),('identity','SSH Key','',False)],
              tabs=True,secure_tab=secure,secure_fields=[('new_user','New user','keep-this-user',False),('new_identity','SSH Key','',False)],key_pickers={'identity','new_identity'})
    parent=asyncio.create_task(ui.show(form))
    await settled(lambda:ui.modal is form)
    ui.form_fields()
    index=3 if secure else 1
    ui.focus=index;ui.modal_key('\n')
    await settled(lambda:not ui.key_picker['loading'])
    assert ui.key_picker['rows'][-1][1]==IMPORT_KEY
    picker=ui.key_picker
    ui.modal_key(curses.KEY_END);ui.modal_key('\n')
    await settled(lambda:isinstance(ui.modal,FileBrowser) and not ui.modal.loading)
    # Cancel preserves both the key list and its underlying connection form.
    ui.modal_key('\x1b')
    await settled(lambda:ui.modal is form and not picker.get('importing'))
    assert ui.key_picker is picker and ui.values[0]=='keep-this-alias' and not parent.done()
    ui.modal_key('\n')
    await settled(lambda:isinstance(ui.modal,FileBrowser) and not ui.modal.loading)
    ui.dismiss(str(source))
    await settled(lambda:isinstance(ui.modal,Form) and ui.modal.title=='Import Key')
    submit(ui,['imported-device',''])
    await settled(lambda:ui.modal is form and ui.key_picker is None)
    assert ui.values[index]==str(tmp_path/'imported-device')
    assert ui.values[0]=='keep-this-alias'
    if secure:assert ui.values[2]=='keep-this-user'
    assert not parent.done()
    ui.modal_key('\x1b');assert await parent is None


def test_import_downloaded_pem_with_browser_permissions(tmp_path):
    from ssh_manager.key_import import matching_public_key
    source=tmp_path/'Downloads'/'lightsail.pem';source.parent.mkdir()
    subprocess.run(['ssh-keygen','-q','-t','rsa','-b','2048','-m','PEM','-N','','-f',str(source)],check=True)
    source.with_suffix('.pem.pub').unlink()
    original=source.read_bytes();source.chmod(0o644)
    destination=tmp_path/'ssh'
    imported=Path(import_key(source,destination,'lightsail.pem'))
    assert imported.name=='lightsail.pem.pub'
    assert source.read_bytes()==original and source.stat().st_mode & 0o777==0o644
    private=destination/'lightsail.pem'
    assert private.read_bytes()==original and private.stat().st_mode & 0o777==0o600
    assert matching_public_key(private)


@pytest.mark.asyncio
async def test_secure_current_key_browses_without_import(tmp_path):
    from ssh_manager.controller import Form, BROWSE_KEY
    source=tmp_path/'Downloads'/'temporary.pem'
    create_key(source,'temporary','')
    app=setup(tmp_path);ui=Console(app)
    form=Form('Add Connection',[('identity','SSH Key','',False)],tabs=True,secure_tab=True,key_pickers={'identity'})
    task=asyncio.create_task(ui.show(form));await settled(lambda:ui.modal is form)
    ui.focus=0;ui.modal_key('\n');await settled(lambda:not ui.key_picker['loading'])
    assert ui.key_picker['rows'][-1][:2]==('Browse Key',BROWSE_KEY)
    ui.modal_key(curses.KEY_END);ui.modal_key('\n')
    await settled(lambda:isinstance(ui.modal,FileBrowser) and not ui.modal.loading)
    ui.dismiss(str(source))
    await settled(lambda:ui.modal is form and ui.key_picker is None)
    assert ui.values[0]==str(source) and not (tmp_path/'temporary.pem').exists()
    assert not any(k['path']==str(source)+'.pub' for k in app.key_rows)
    ui.modal_key('\x1b');await task


@pytest.mark.asyncio
async def test_browser_command_bar_shows_path_then_filter(tmp_path,monkeypatch):
    monkeypatch.setattr(curses,'has_colors',lambda:False)
    app=setup(tmp_path);ui=Console(app);ui.win=Window()
    task=asyncio.create_task(ui.show(FileBrowser(directory=tmp_path)))
    await settled(lambda:ui.modal is not None and not ui.modal.loading)
    browser=ui.modal
    ui.focus=next(i for i,row in enumerate(browser.visible_entries) if row[0]=='data')
    ui.draw()
    text=''.join(t for _,_,t,_ in ui.win.writes)
    assert 'Search > ' in text and str(tmp_path/'data') in text
    ui.win.writes.clear();ui.modal_key('d');ui.draw()
    assert any(t=='Search > d' for _,_,t,_ in ui.win.writes)
    ui.modal_key('\x1b');ui.modal_key('\x1b');await task
