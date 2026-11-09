import json
from types import SimpleNamespace
import pytest
from ssh_manager.config import SSHConfig, Host
from ssh_manager.store import Store, Vault
from ssh_manager import network
from ssh_manager.remote import Remote, SCRIPT


def test_config_preserves_options_and_comments_and_conflicts(tmp_path):
    path = tmp_path/'config'
    path.write_text('# header\nHost alpha\n HostName 192.0.2.1\n User admin\n # special\n ProxyJump bastion\nHost *\n ServerAliveInterval 10\n')
    cfg = SSHConfig(path)
    host = cfg.discover(False)[0]
    cfg.save(dict(alias='alpha', hostname='192.0.2.2', user='admin', port='2222', identity='~/.ssh/id_x'), host)
    content = path.read_text()
    assert '# special' in content and 'ProxyJump bastion' in content
    assert 'ServerAliveInterval 10' in content and '192.0.2.2' in content
    assert list((tmp_path/'.ssh-manager-backups').glob('*.bak'))
    with pytest.raises(ValueError, match='changed outside'):
        cfg.remove(host)


def test_includes_wildcards_shared_duplicate_and_new_includes(tmp_path):
    (tmp_path/'parts').mkdir()
    path = tmp_path/'config'
    path.write_text('Include parts/*\nHost *\n User default\nHost one two\n HostName localhost\nHost dup\n HostName localhost\nHost dup\n Port 2222\n')
    (tmp_path/'parts'/'a').write_text('Host included\n HostName localhost\n')
    cfg = SSHConfig(path)
    hosts = {h.alias:h for h in cfg.discover(False)}
    assert set(hosts) == {'included','one','two','dup'}
    assert hosts['one'].patterns == ['one','two']
    with pytest.raises(ValueError, match='Shared'):
        cfg.remove(hosts['one'])
    with pytest.raises(ValueError, match='Shared'):
        cfg.remove(hosts['dup'])
    assert not cfg.needs_refresh()
    (tmp_path/'parts'/'b').write_text('Host extra\n HostName localhost\n')
    assert cfg.needs_refresh()


def test_new_config_precedes_defaults(tmp_path):
    path = tmp_path/'config'
    path.write_text('Host *\n User fallback\n')
    cfg = SSHConfig(path)
    cfg.save(dict(alias='new', hostname='localhost', user='desired', port='22'))
    hosts = cfg.discover()
    assert hosts[0].user == 'desired'


def test_store_rename_retains_uuid_and_archive(tmp_path):
    store = Store(tmp_path)
    a = Host('old',tmp_path/'config',0,1,['old'],'',hostname='192.0.2.1',user='u')
    store.reconcile([a]); original = store.get('old')['id']
    store.update('old', notes='hello')
    a.alias='new'
    store.reconcile([a])
    assert store.get('new')['id'] == original
    assert store.get('new')['notes'] == 'hello'
    store.reconcile([])
    assert store.archive()[0]['alias'] == 'new'


def test_store_ambiguous_rename_is_not_guessed(tmp_path):
    store = Store(tmp_path)
    hosts=[Host(n,tmp_path/'c',0,1,[n],'',hostname='192.0.2.1',user='u') for n in ('a','b')]
    store.reconcile(hosts)
    original = store.get('a')['id']
    hosts[0].alias='c';hosts[1].alias='d'
    store.reconcile(hosts)
    assert store.get('c')['id'] != original
    assert len(store.archive()) == 2


def test_vault_round_trip_and_wrong_password(tmp_path):
    vault = Vault(tmp_path)
    vault.unlock('a long master password')
    vault.put('uuid','root','sensitive password','note')
    assert 'sensitive password' not in vault.path.read_text()
    vault.lock()
    assert vault.records == {} and vault.cipher is None
    with pytest.raises(ValueError, match='Incorrect'):
        vault.unlock('wrong password')
    vault.unlock('a long master password')
    assert vault.for_server('uuid')[0]['password'] == 'sensitive password'


def test_proxy_does_not_probe_directly(monkeypatch, tmp_path):
    h=Host('a',tmp_path/'c',0,1,['a'],'',proxy='jump')
    monkeypatch.setattr(network.socket,'create_connection',lambda *a,**k:pytest.fail('must not connect'))
    assert network.check(h)['status']=='VIA PROXY'


def test_dns_verification(monkeypatch):
    class Resolver:
        def resolve(self,name,kind): return ['203.0.113.1'] if kind=='A' else []
    monkeypatch.setattr(network.dns.resolver,'Resolver',Resolver)
    rows=network.verify_domains([dict(name='example.com',source='Manual')],['203.0.113.1'])
    assert rows[0]['status']=='POINTS HERE'
    assert network.valid_domain('Example.COM.') == 'example.com'
    with pytest.raises(ValueError): network.valid_domain('https://example.com/path')


def test_remote_password_not_in_arguments(monkeypatch,tmp_path):
    recorded=[]
    def run(args,**kwargs):
        recorded.append((args,kwargs))
        return SimpleNamespace(returncode=0,stdout='Password updated',stderr='')
    monkeypatch.setattr('ssh_manager.remote.subprocess.run',run)
    host=Host('test',tmp_path/'config',0,1,['test'],'',user='admin')
    Remote(SSHConfig(tmp_path/'config')).run(host,'password',user='user',password='secret-value')
    args,kwargs=recorded[0]
    assert 'secret-value' not in ' '.join(args)
    assert json.loads(kwargs['input'])['password']=='secret-value'
    assert 'StrictHostKeyChecking=yes' in args


def test_remote_script_compiles():
    compile(SCRIPT,'<remote>','exec')


def test_add_preserves_global_preamble_for_other_hosts(tmp_path):
    path=tmp_path/'config'
    path.write_text('User original\nServerAliveInterval 25\nHost existing\n HostName localhost\n')
    cfg=SSHConfig(path)
    cfg.save(dict(alias='new',hostname='localhost',user='different',port='22'))
    hosts={h.alias:h for h in cfg.discover()}
    assert hosts['existing'].user=='original'
    assert hosts['new'].user=='different'


def test_remote_authorized_keys_preserves_options_and_rejects_symlinks(tmp_path, monkeypatch):
    import base64, contextlib, io, os, pwd
    home=tmp_path/'home';home.mkdir()
    u=SimpleNamespace(pw_dir=str(home),pw_uid=os.getuid(),pw_gid=os.getgid())
    monkeypatch.setattr(pwd,'getpwnam',lambda name:u)
    key='ssh-ed25519 '+base64.b64encode(b'test-key-blob').decode()+' test'
    def execute(op,key):
        monkeypatch.setattr('sys.stdin',io.StringIO(json.dumps(dict(op=op,user='test',key=key))))
        with contextlib.redirect_stdout(io.StringIO()):exec(compile(SCRIPT,'<remote>','exec'),{})
    execute('add-key',key)
    path=home/'.ssh'/'authorized_keys'
    restricted='restrict,command="echo hello world" '+key
    path.write_text(restricted+'\n# keep this comment\n')
    execute('add-key',key)
    assert path.read_text().count('ssh-ed25519')==1
    assert restricted in path.read_text()
    execute('revoke-key',key)
    assert path.read_text()=='# keep this comment\n'
    assert list(path.parent.glob('authorized_keys.*.bak'))
    path.unlink();path.symlink_to(tmp_path/'elsewhere')
    with pytest.raises(ValueError,match='Symlinked'):
        execute('add-key',key)
