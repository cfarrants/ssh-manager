from __future__ import annotations
import base64
import datetime as dt
import json
import os
from pathlib import Path
import sqlite3
import threading
import uuid
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from .config import atomic_write
from .credentials import get_key, store_key, SecureStorageError


# Existing vaults depend on this protocol identifier; it is not an app name.
VAULT_DERIVATION_ID = b'server-manager/vault/application/v1'


class LegacyVaultPasswordRequired(ValueError):
    pass


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, directory: Path):
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(directory / "inventory.sqlite3", check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS servers(id TEXT PRIMARY KEY,alias TEXT UNIQUE,signature TEXT,active INTEGER,data TEXT);
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,at TEXT,server TEXT,action TEXT,result TEXT);
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT);
        ''')
        if os.name != "nt":
            (directory / "inventory.sqlite3").chmod(0o600)
        self.db.commit()

    def audit(self, server, action, result):
        with self.lock, self.db:
            self.db.execute("INSERT INTO events(at,server,action,result) VALUES(?,?,?,?)", (now(), server, action, result))

    def events(self):
        with self.lock:
            return [dict(r) for r in self.db.execute("SELECT * FROM events ORDER BY id DESC LIMIT 1000")]

    def setting(self, key, default=None):
        with self.lock:
            row = self.db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
            return json.loads(row[0]) if row else default

    def set_setting(self, key, value):
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO settings VALUES(?,?)", (key, json.dumps(value)))

    def reconcile(self, hosts):
        """Only unique endpoint matches migrate metadata across external renames."""
        with self.lock, self.db:
            rows = [dict(r) for r in self.db.execute("SELECT * FROM servers")]
            aliases = {h.alias for h in hosts}
            known = {r["alias"]: r for r in rows}
            counts = {}
            for h in hosts:
                counts[h.signature] = counts.get(h.signature, 0) + 1
            for h in hosts:
                if h.alias in known:
                    self.db.execute("UPDATE servers SET signature=?,active=1 WHERE alias=?", (h.signature, h.alias))
                    continue
                candidates = [r for r in rows if r["alias"] not in aliases and r["signature"] == h.signature]
                if len(candidates) == 1 and counts[h.signature] == 1 and not h.error:
                    old = candidates[0]
                    self.db.execute("UPDATE servers SET alias=?,active=1 WHERE id=?", (h.alias, old["id"]))
                    self.audit(h.alias, "Config sync", f"Alias renamed from {old['alias']}; inventory retained")
                else:
                    self.db.execute("INSERT INTO servers VALUES(?,?,?,?,?)", (str(uuid.uuid4()), h.alias, h.signature, 1, "{}"))
            for row in self.db.execute("SELECT id,alias FROM servers").fetchall():
                if row["alias"] not in aliases:
                    self.db.execute("UPDATE servers SET active=0 WHERE id=?", (row["id"],))

    def rename(self, old, new):
        with self.lock, self.db:
            self.db.execute("UPDATE servers SET alias=? WHERE alias=?", (new, old))

    def get(self, alias):
        with self.lock:
            row = self.db.execute("SELECT * FROM servers WHERE alias=?", (alias,)).fetchone()
            return {"id": row["id"], **json.loads(row["data"])} if row else {}

    def update(self, alias, **changes):
        with self.lock, self.db:
            data = self.get(alias)
            data.pop("id", None)
            data.update(changes)
            self.db.execute("UPDATE servers SET data=? WHERE alias=?", (json.dumps(data), alias))

    def archive(self):
        with self.lock:
            return [dict(r) for r in self.db.execute("SELECT alias,signature FROM servers WHERE active=0")]

    def record_account_password(self, alias, user):
        """Associate the account inventory with its encrypted Vault record."""
        with self.lock:
            data = self.get(alias)
            if not data.get('id'):
                raise ValueError('Server must be in the inventory before recording an account.')
            users = data.get('users', [])
            account = next((item for item in users if item['user']==user), None)
            if account is None:
                account = dict(user=user,uid=None,home='',shell='',keys=[],inspected=None)
                users.append(account)
            account.update(password_ref=f"{data['id']}:{user}",credential_updated=now())
            self.update(alias, users=users)


class LegacyApplicationVaultError(ValueError):
    pass


class Vault:
    def __init__(self, directory):
        self.path=Path(directory)/'vault.json'
        self.cipher=None;self.records={};self.salt=None
        self.protection='password';self.kdf='scrypt';self.key_id=None

    @staticmethod
    def _derive(password,salt,kdf):
        if kdf=='hkdf-sha256':
            return HKDF(algorithm=hashes.SHA256(),length=32,salt=salt,info=VAULT_DERIVATION_ID).derive(password.encode())
        if kdf=='scrypt':return Scrypt(salt=salt,length=32,n=2**17,r=8,p=1).derive(password.encode())
        raise ValueError('Unsupported legacy vault encryption format.')

    @classmethod
    def _legacy_records(cls,payload,password):
        salt=base64.b64decode(payload['salt'])
        cipher=Fernet(base64.urlsafe_b64encode(cls._derive(password,salt,payload.get('kdf','scrypt'))))
        try:records=json.loads(cipher.decrypt(payload['token'].encode()))
        except InvalidToken:raise ValueError('Incorrect master password or damaged vault.') from None
        return cipher,records,salt

    def unlock(self,password):
        """Compatibility API for password-protected vaults; normal use is OS-backed."""
        if self.path.exists():
            payload=json.loads(self.path.read_text())
            if payload.get('protection')=='keyring':
                self.open_automatic();return
            self.cipher,self.records,self.salt=self._legacy_records(payload,password)
            self.protection=payload.get('protection','password');self.kdf=payload.get('kdf','scrypt')
        else:
            if len(password)<12:raise ValueError('Choose a master password of at least 12 characters.')
            self.salt=os.urandom(16)
            self.cipher=Fernet(base64.urlsafe_b64encode(self._derive(password,self.salt,'scrypt')))
            self.records={};self.protection='password';self.kdf='scrypt'
            try:self.save()
            except Exception:self.lock();raise

    @staticmethod
    def _decode_os(payload):
        if payload.get('version')!=2 or payload.get('protection')!='keyring':raise ValueError('Unsupported vault format.')
        key=get_key(payload['key_id'])
        try:
            cipher=Fernet(key);records=json.loads(cipher.decrypt(payload['token'].encode()))
        except (InvalidToken,ValueError):raise ValueError('The vault could not be decrypted with its OS-stored key. It was not overwritten.') from None
        if not isinstance(records,dict):raise ValueError('Invalid vault records.')
        return cipher,records

    def open_automatic(self):
        if self.cipher and self.protection=='keyring':return
        if self.path.exists():
            payload=json.loads(self.path.read_text())
            if payload.get('protection')=='application':
                raise LegacyApplicationVaultError('This older vault needs a one-time migration. Run ssh-manager --migrate-vault --legacy-key-file PATH using the previous version’s vault_key.py. The vault has not been modified.')
            if payload.get('protection')!='keyring':raise LegacyVaultPasswordRequired('The existing vault needs its old master password once to migrate to OS-protected storage.')
            cipher,records=self._decode_os(payload)
            self.cipher,self.records,self.key_id=cipher,records,payload['key_id']
            self.protection='keyring';self.salt=None;return
        key_id=uuid.uuid4().hex;key=Fernet.generate_key()
        store_key(key_id,key)
        self.cipher=Fernet(key);self.records={};self.key_id=key_id;self.protection='keyring';self.salt=None
        try:self.save()
        except Exception:self.lock();raise

    def migrate_to_automatic(self,password):
        """Convert a legacy vault and verify a new-key-encrypted recovery copy."""
        original=self.path.read_bytes()
        payload=json.loads(original)
        if payload.get('protection')=='keyring':self.open_automatic();return None
        try:
            _,records,_=self._legacy_records(payload,password)
            key_id=uuid.uuid4().hex;key=Fernet.generate_key()
            store_key(key_id,key)
            cipher=Fernet(key)
            converted=dict(version=2,protection='keyring',key_id=key_id,token=cipher.encrypt(json.dumps(records).encode()).decode())
            _,verified=self._decode_os(converted)
            if verified!=records:raise ValueError('Vault verification failed; original retained.')
            content=json.dumps(converted).encode()
            backup=self.path.with_name('vault.pre-keyring-backup-'+uuid.uuid4().hex+'.json')
            atomic_write(backup,content)
            if self._decode_os(json.loads(backup.read_bytes()))[1]!=records:
                raise ValueError('Recovery copy verification failed; original retained.')
            if self.path.read_bytes()!=original:raise ValueError('The vault changed during migration. Nothing was overwritten; close other app instances and retry.')
            try:
                atomic_write(self.path,content)
                cipher,verified=self._decode_os(json.loads(self.path.read_bytes()))
                if verified!=records:raise ValueError('Migrated vault verification failed.')
            except Exception:
                if self.path.read_bytes()==content:atomic_write(self.path,original)
                raise
            self.cipher,self.records,self.key_id=cipher,verified,key_id
            self.protection='keyring';self.salt=None
            return backup
        except Exception:self.lock();raise

    def save(self):
        if not self.cipher:raise ValueError('Open saved passwords first.')
        if self.protection=='keyring':
            token=self.cipher.encrypt(json.dumps(self.records).encode()).decode()
            payload=dict(version=2,protection='keyring',key_id=self.key_id,token=token)
            if self._decode_os(payload)[1]!=self.records:raise ValueError('Vault encryption verification failed; nothing was written.')
        else:
            payload=dict(version=1,protection=self.protection,kdf=self.kdf,salt=base64.b64encode(self.salt).decode(),token=self.cipher.encrypt(json.dumps(self.records).encode()).decode())
        atomic_write(self.path,json.dumps(payload).encode())

    def lock(self):
        self.records = {}
        self.cipher = None
        self.salt = None

    def put(self, server_id, user, password, notes=""):
        if not self.cipher:
            raise ValueError("Unlock the vault first.")
        previous=self.records.copy()
        self.records[f"{server_id}:{user}"] = {"server": server_id, "user": user, "password": password, "notes": notes, "updated": now()}
        try:self.save()
        except Exception:
            self.records=previous
            raise

    def for_server(self, server_id):
        return [r for r in self.records.values() if r["server"] == server_id]
