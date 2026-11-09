import pytest
from ssh_manager.controller import SSHManager
from ssh_manager.config import Host
from ssh_manager.network import ping


@pytest.mark.asyncio
async def test_live_ping_updates_table_without_database_writes(tmp_path,monkeypatch):
    app=SSHManager(tmp_path/'config',tmp_path/'data')
    host=Host('one',tmp_path/'config',0,1,['one'],'',hostname='192.0.2.1',user='admin')
    app.hosts=[host];app.store.reconcile(app.hosts)
    app.selected_alias='one'
    previous=app.store.get('one')
    events=app.store.events()
    responses=iter([dict(status='ONLINE',latency=12),dict(status='OFFLINE')])
    monkeypatch.setattr('ssh_manager.controller.ping',lambda h:next(responses))
    await app.ping_all.__wrapped__(app)
    assert app.headers==['SSH ALIAS','HOST / IP','USER','PORT','PING','STATUS']
    assert app.rows[0][1][4]=='12 ms' and app.rows[0][1][5]=='ONLINE'
    await app.ping_all.__wrapped__(app)
    assert app.rows[0][1][4]=='—' and app.rows[0][1][5]=='OFFLINE'
    assert app.store.get('one')==previous and app.store.events()==events
    app.store.update('one',monitor=False)
    await app.ping_all.__wrapped__(app)
    app.render_table()
    assert app.rows[0][1][5]=='PAUSED' and app.rows[0][1][4]=='—'


def test_ping_skips_proxy_routes_and_bad_config(tmp_path,monkeypatch):
    def fail(*args,**kwargs):pytest.fail('No connection should be attempted')
    monkeypatch.setattr('ssh_manager.network.socket.create_connection',fail)
    host=Host('one',tmp_path/'config',0,1,['one'],'',hostname='example.com',user='admin')
    host.proxy=True
    assert ping(host)['status']=='VIA PROXY'
    host.proxy=False;host.error='invalid'
    assert ping(host)['status']=='CONFIG ERROR'
