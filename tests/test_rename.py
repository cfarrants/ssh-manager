from pathlib import Path
from ssh_manager.paths import data_path
from ssh_manager.store import Vault


def test_existing_inventory_and_vault_migrate_without_reencryption(tmp_path,monkeypatch):
    monkeypatch.setattr('ssh_manager.paths.sys.platform','linux')
    monkeypatch.setenv('XDG_DATA_HOME',str(tmp_path))
    legacy=tmp_path/'server-manager';legacy.mkdir()
    (legacy/'inventory.sqlite3').write_bytes(b'test inventory')
    old=Vault(legacy);old.open_automatic();old.put('server','user','saved-password')
    encrypted=old.path.read_bytes();old.lock()
    migrated=data_path()
    assert migrated==tmp_path/'ssh-manager' and not legacy.exists()
    assert (migrated/'inventory.sqlite3').read_bytes()==b'test inventory'
    assert (migrated/'vault.json').read_bytes()==encrypted
    vault=Vault(migrated);vault.open_automatic()
    assert vault.records['server:user']['password']=='saved-password'
    assert data_path()==migrated


def test_existing_new_data_folder_is_not_overwritten(tmp_path,monkeypatch):
    monkeypatch.setattr('ssh_manager.paths.sys.platform','linux')
    monkeypatch.setenv('XDG_DATA_HOME',str(tmp_path))
    legacy=tmp_path/'server-manager';legacy.mkdir();(legacy/'marker').write_text('old')
    current=tmp_path/'ssh-manager';current.mkdir();(current/'marker').write_text('new')
    assert data_path()==current
    assert (legacy/'marker').read_text()=='old' and (current/'marker').read_text()=='new'
