import base64
import json
import os
import pytest
from cryptography.fernet import Fernet
from ssh_manager import credentials,store
from ssh_manager.store import Vault, LegacyApplicationVaultError


def legacy(directory):
    path=directory/'vault.json';directory.mkdir(exist_ok=True)
    salt=os.urandom(16);password='example-legacy-test-secret'
    cipher=Fernet(base64.urlsafe_b64encode(Vault._derive(password,salt,'hkdf-sha256')))
    records={'server:user':dict(server='server',user='user',password='saved-test-password')}
    payload=dict(version=1,protection='application',kdf='hkdf-sha256',salt=base64.b64encode(salt).decode(),token=cipher.encrypt(json.dumps(records).encode()).decode())
    path.write_text(json.dumps(payload));return path,password,records


def test_application_vault_migrates_to_unique_os_key_and_verified_backup(tmp_path):
    path,password,records=legacy(tmp_path)
    original=path.read_bytes();vault=Vault(tmp_path)
    with pytest.raises(LegacyApplicationVaultError):vault.open_automatic()
    assert path.read_bytes()==original
    backup=vault.migrate_to_automatic(password)
    payload=json.loads(path.read_text())
    assert payload['version']==2 and payload['protection']=='keyring'
    assert 'salt' not in payload and 'kdf' not in payload
    assert records==vault.records
    assert password not in path.read_text() and 'saved-test-password' not in path.read_text()
    vault.lock();vault.open_automatic();assert vault.records==records
    recovery=Vault(tmp_path);recovery.path=backup;recovery.open_automatic()
    assert recovery.records==records and backup.stat().st_mode & 0o777==0o600
    another=Vault(tmp_path/'other');another.open_automatic()
    assert another.key_id!=vault.key_id


def test_missing_os_key_never_replaces_vault(tmp_path,isolated_credential_store):
    vault=Vault(tmp_path);vault.open_automatic();vault.put('server','user','secret')
    original=vault.path.read_bytes();vault.lock()
    isolated_credential_store.values.clear()
    with pytest.raises(credentials.SecureStorageError,match='missing'):vault.open_automatic()
    assert vault.path.read_bytes()==original and vault.cipher is None


def test_keyring_failure_preserves_legacy_vault(tmp_path,monkeypatch):
    path,password,_=legacy(tmp_path);original=path.read_bytes()
    def fail(*args):raise credentials.SecureStorageError('Credential store locked')
    monkeypatch.setattr(store,'store_key',fail)
    with pytest.raises(credentials.SecureStorageError):Vault(tmp_path).migrate_to_automatic(password)
    assert path.read_bytes()==original and list(tmp_path.glob('*backup*'))==[]


def test_migration_write_failure_retains_original_and_recoverable_backup(tmp_path,monkeypatch):
    path,password,records=legacy(tmp_path);original=path.read_bytes()
    write=store.atomic_write
    def fail(destination,content,*args,**kwargs):
        if destination==path:raise OSError('Disk write failed')
        return write(destination,content,*args,**kwargs)
    monkeypatch.setattr(store,'atomic_write',fail)
    with pytest.raises(OSError):Vault(tmp_path).migrate_to_automatic(password)
    assert path.read_bytes()==original
    recovery=Vault(tmp_path);recovery.path=next(tmp_path.glob('*backup*'));recovery.open_automatic()
    assert recovery.records==records


def test_migration_preserves_concurrent_file_change(tmp_path,monkeypatch):
    path,password,_=legacy(tmp_path);original=path.read_bytes()
    save_key=store.store_key
    def changed(key_id,key):
        save_key(key_id,key);path.write_bytes(original+b'\n')
    monkeypatch.setattr(store,'store_key',changed)
    with pytest.raises(ValueError,match='changed during migration'):Vault(tmp_path).migrate_to_automatic(password)
    assert path.read_bytes()==original+b'\n'


def test_insecure_or_null_backend_rejected(monkeypatch):
    class Insecure:
        priority=10
    Insecure.__module__='keyrings.alt.file'
    monkeypatch.setattr(credentials.keyring,'get_keyring',lambda:Insecure())
    with pytest.raises(credentials.SecureStorageError,match='No supported OS'):credentials._select_backend()


def test_write_must_be_read_back_from_credential_store(monkeypatch):
    class Broken:
        def get_password(self,*args):return None
        def set_password(self,*args):pass
    monkeypatch.setattr(credentials,'_backend',lambda:Broken())
    with pytest.raises(credentials.SecureStorageError,match='verify'):credentials.store_key('test-id',Fernet.generate_key())


def test_lost_key_during_save_preserves_disk_and_in_memory_records(tmp_path,isolated_credential_store):
    vault=Vault(tmp_path);vault.open_automatic();vault.put('server','user','original')
    original=vault.path.read_bytes();isolated_credential_store.values.clear()
    with pytest.raises(credentials.SecureStorageError,match='missing'):
        vault.put('server','user','replacement')
    assert vault.records['server:user']['password']=='original'
    assert vault.path.read_bytes()==original
