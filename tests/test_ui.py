import pytest
from ssh_manager.controller import SSHManager, ADD_CONNECTION

@pytest.mark.asyncio
async def test_rotation_failure_never_revokes_old_key(tmp_path,monkeypatch):
    app=SSHManager(tmp_path/'config',tmp_path/'data',demo=True)
    path=tmp_path/'config';path.write_text('Host target\n HostName localhost\n User admin\n')
    host=app.config.discover()[0]
    calls=[]
    def remote_run(host,op,**kwargs):calls.append(op);return 'done'
    def fail(*args):raise RuntimeError('new key rejected')
    monkeypatch.setattr(app.remote,'run',remote_run)
    monkeypatch.setattr(app.remote,'verify_key',fail)
    with pytest.raises(RuntimeError,match='rejected'):
        await app.rotate(host,dict(user='admin',newkey='ssh-ed25519 AAAA',oldkey='ssh-ed25519 BBBB',newpath='/tmp/newkey'))
    assert calls==['add-key']
    assert 'IdentityFile' not in path.read_text()

@pytest.mark.asyncio
async def test_bulk_rotation_updates_shared_config_and_orders_revocation(tmp_path,monkeypatch):
    from ssh_manager.config import digest
    path=tmp_path/'config'
    path.write_text('Host one\n HostName localhost\n User admin\n IdentityFile /old\nHost two\n HostName localhost\n User admin\n IdentityFile /old\n')
    app=SSHManager(path,tmp_path/'data',demo=True)
    hosts=app.config.discover();app.hosts=hosts;app.store.reconcile(hosts)
    app.rotation_revisions={str(path):digest(path)}
    calls=[]
    def remote_run(host,op,**kwargs):calls.append((host.alias,op));return 'done'
    def verify(host,key):calls.append((host.alias,'verify'));return True
    async def inspect(host):pass
    monkeypatch.setattr(app.remote,'run',remote_run)
    monkeypatch.setattr(app.remote,'verify_key',verify)
    monkeypatch.setattr(app,'inspect_host',inspect)
    monkeypatch.setattr(app,'refresh_inventory',lambda **kwargs:None)
    for host in hosts:
        await app.rotate(host,dict(user='admin',newkey='ssh-ed25519 AAAA',oldkey='ssh-ed25519 BBBB',newpath='/new'))
    assert calls==[('one','add-key'),('one','verify'),('one','revoke-key'),('two','add-key'),('two','verify'),('two','revoke-key')]
    assert all(h.identities[0]=='/new' for h in app.config.discover())

@pytest.mark.asyncio
async def test_rotation_updates_related_aliases_before_revoke(tmp_path,monkeypatch):
    from ssh_manager.config import digest
    path=tmp_path/'config'
    path.write_text('Host one\n HostName localhost\n User admin\n IdentityFile /old\nHost two\n HostName localhost\n User admin\n IdentityFile /old\n')
    app=SSHManager(path,tmp_path/'data',demo=True)
    app.hosts=app.config.discover();app.store.reconcile(app.hosts)
    app.rotation_revisions={str(path):digest(path)}
    def remote_run(host,op,**kwargs):
        if op=='revoke-key':
            assert all(h.identities[0]=='/new' for h in app.config.discover())
        return 'done'
    async def inspect(host):pass
    monkeypatch.setattr(app.remote,'run',remote_run)
    monkeypatch.setattr(app.remote,'verify_key',lambda *args:True)
    monkeypatch.setattr(app,'inspect_host',inspect)
    monkeypatch.setattr(app,'refresh_inventory',lambda **kwargs:None)
    await app.rotate(app.hosts[0],dict(user='admin',newkey='ssh-ed25519 AAAA',oldkey='ssh-ed25519 BBBB',newpath='/new',related_aliases=['one','two']))
    assert all(h.identities[0]=='/new' for h in app.config.discover())


import asyncio
from contextlib import nullcontext
import curses
from types import SimpleNamespace
from ssh_manager.console import Console
from ssh_manager.controller import Form, Viewer, background
from ssh_manager.config import Host


class Window:
    def __init__(self, height=35, width=120):
        self.height, self.width = height, width
        self.writes = []
        self.keys = []
        self.frames = 0
    def getmaxyx(self): return self.height, self.width
    def erase(self): self.writes.clear()
    def addstr(self, y, x, text, attr=0):
        assert 0 <= y < self.height and 0 <= x < self.width
        self.writes.append((y,x,text,attr))
    def refresh(self): self.frames += 1
    def get_wch(self):
        if not self.keys: raise curses.error()
        return self.keys.pop(0)


@pytest.fixture
def manager(tmp_path):
    return SSHManager(tmp_path/'config',tmp_path/'data',demo=True)


def populate(manager,tmp_path):
    manager.hosts=[Host('test',tmp_path/'config',0,1,['test'],'',hostname='192.0.2.1',user='admin')]
    manager.store.reconcile(manager.hosts)
    manager.selected_alias='test'
    manager.render_table(selected='test')


def test_negative_cursor_empty_views_and_selection_restoration(manager,tmp_path):
    manager.cursor=-1
    assert manager.row_id() is None
    manager.render_table()
    for view in ('accounts','activity','connections'):
        manager.cursor=-1
        manager.action_view(view)
        assert manager.row_id() == (ADD_CONNECTION if view == 'connections' else ':add-key:' if view=='accounts' else None)
    populate(manager,tmp_path)
    manager.cursor=-1
    manager.render_table()
    assert manager.cursor==0 and manager.row_id()=='test'
    for view in ('accounts','activity','connections'):
        manager.action_view(view)
    assert manager.row_id()=='test'


def test_native_tabs_filter_and_resize(manager,tmp_path,monkeypatch):
    monkeypatch.setattr(curses,'has_colors',lambda:False)
    populate(manager,tmp_path)
    ui=Console(manager);ui.win=Window()
    ui.handle_key('k')
    assert manager.view=='accounts' and len(manager.rows)==3
    ui.handle_key('/')
    ui.handle_key('z')
    assert len(manager.rows)==2  # Key actions remain available while filtering.
    ui.handle_key('\x1b')
    assert len(manager.rows)==3
    ui.handle_key('\t')
    assert manager.view=='activity'
    ui.handle_key(curses.KEY_LEFT)
    assert manager.view=='activity'
    ui.handle_key('k')
    assert manager.view=='accounts'
    ui.draw()
    ui.win=Window(18,60);ui.draw()
    ui.win=Window(10,30);ui.draw()
    assert any('Enlarge' in text for _,_,text,_ in ui.win.writes)


@pytest.mark.asyncio
async def test_forms_mask_passwords_and_clear_after_dismiss(manager,monkeypatch):
    monkeypatch.setattr(curses,'has_colors',lambda:False)
    ui=Console(manager);ui.win=Window()
    task=asyncio.create_task(ui.show(Form('Vault',[('password','Password','private-secret',True)])))
    await asyncio.sleep(0)
    ui.draw()
    assert not any('private-secret' in text for _,_,text,_ in ui.win.writes)
    ui.modal_key('\n');ui.modal_key('\n')
    assert await task=={'password':'private-secret'}
    assert ui.modal is None and ui.values==[]
    viewer=Viewer('Password','private-secret',True)
    task=asyncio.create_task(ui.show(viewer));await asyncio.sleep(0)
    ui.close_secret();await task
    assert viewer.value=='' and ui.modal is None


@pytest.mark.asyncio
async def test_operations_cancel_and_busy_guard(manager):
    ui=Console(manager)
    task=asyncio.create_task(ui.show(Form('Confirm',[('confirm','Confirm','',False)])))
    await asyncio.sleep(0);ui.modal_key('\x1b')
    assert await task is None
    manager.busy=True
    ui.handle_key('k');ui.handle_key('q')
    assert manager.view=='connections' and manager.is_running


@pytest.mark.asyncio
async def test_return_from_interactive_ssh(manager,tmp_path,monkeypatch):
    populate(manager,tmp_path)
    manager.demo=False
    ui=Console(manager)
    monkeypatch.setattr(ui,'suspend',nullcontext)
    monkeypatch.setattr('ssh_manager.controller.subprocess.run',lambda *a,**kw:SimpleNamespace(returncode=0))
    await manager.action_open()
    assert 'Returned from test' in manager.message
    for key in ('5','1'):
        ui.handle_key(key)
    assert manager.row_id()=='test'


@pytest.mark.asyncio
async def test_add_connection_preserves_backend_workflow(manager,tmp_path):
    manager.demo=False
    class UI:
        async def show(self,form):
            return dict(alias='newhost',hostname='localhost',user='admin',port='22',identity='')
    manager.ui=UI()
    await manager.action_add()
    await manager.jobs['config']
    assert manager.hosts[0].alias=='newhost'
    assert 'Host newhost' in (tmp_path/'config').read_text()


@pytest.mark.asyncio
async def test_background_jobs_never_cancel_mutation(manager):
    gate=asyncio.Event()
    @background('mutation')
    async def mutate(self):
        await gate.wait()
        self.message='done'
    first=mutate(manager)
    second=mutate(manager)
    assert first is second and not first.cancelled()
    gate.set();await first
    assert manager.message=='done'


@pytest.mark.asyncio
async def test_native_event_loop_exits_without_framework(manager,monkeypatch):
    monkeypatch.setattr(curses,'has_colors',lambda:False)
    ui=Console(manager)
    monkeypatch.setattr(ui,'setup',lambda:None)
    win=Window();win.keys=['2','3','4','5','6','1','q']
    await asyncio.wait_for(ui.run(win),timeout=2)
    assert not manager.is_running and win.frames>=1


@pytest.mark.asyncio
async def test_page_letters_and_tab_do_not_change_form_focus(manager,monkeypatch):
    monkeypatch.setattr(curses,'has_colors',lambda:False)
    ui=Console(manager);ui.win=Window()
    ui.handle_key('K');assert manager.view=='accounts'
    ui.handle_key('a');assert manager.view=='activity'
    ui.handle_key(curses.KEY_LEFT);assert manager.view=='activity'
    ui.handle_key('c');assert manager.view=='connections'
    form=Form('Test',[('name','Name','keep this',False)])
    task=asyncio.create_task(ui.show(form));await asyncio.sleep(0)
    focus=ui.focus
    ui.handle_key('\t')
    assert manager.view=='accounts' and ui.modal is form and ui.focus==focus
    assert ui.values==['keep this']
    ui.handle_key(curses.KEY_BTAB)
    assert manager.view=='connections' and ui.focus==focus
    ui.modal_key('\x1b');await task
    ui.draw()
    assert any(text=='SSH MANAGER' and row==1 for row,_,text,_ in ui.win.writes)
    assert any(text=='C' and attr & curses.A_UNDERLINE and attr & curses.A_REVERSE for _,_,text,attr in ui.win.writes)
