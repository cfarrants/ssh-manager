from __future__ import annotations
import asyncio
from contextlib import nullcontext
from dataclasses import dataclass, field
from functools import wraps
import json
import getpass
import socket
import os
from pathlib import Path
import shlex
import subprocess
import time
from .file_browser import FileBrowser
from .paths import data_path
from .config import SSHConfig
from .store import Store, Vault, now, LegacyVaultPasswordRequired
from .network import check, ping, reverse, valid_domain, verify_domains
from .remote import Remote, local_keys, create_key

VIEWS = ("connections", "accounts", "activity")
ADD_KEY = ":add-key:"
IMPORT_KEY = ":import-key:"
BROWSE_KEY = ":browse-key:"
ADD_CONNECTION = ':add-connection:'

@dataclass
class Form:
    title: str
    fields: list
    help_text: str = ""
    submit: str = "Save"
    delete: bool = False
    tabs: bool = False
    secure_tab: bool = False
    secure_fields: list = field(default_factory=list)
    choices: dict = field(default_factory=dict)
    sections: dict = field(default_factory=dict)
    existing_sections: dict = field(default_factory=dict)
    key_pickers: set = field(default_factory=set)
    conditional_hide: tuple | None = None
    submit_handler: object = None
    submit_status: str = 'Working…'
    error: str = ''
    submitting: bool = False
    overview: bool = False
    cancel: str = 'Cancel'
    default_cancel: bool = False
    text_colour: int = 6
    placeholders: dict = field(default_factory=dict)
    highlights: dict = field(default_factory=dict)
    read_only: set = field(default_factory=set)
    key_list_only: bool = False

@dataclass
class Viewer:
    title: str
    value: str
    secret: bool = False
    compact: bool = False

@dataclass
class ProgressComplete:
    title: str

@dataclass
class KeyAdmin:
    account: str
    keys: list = field(default_factory=list)
    loading: bool = True
    error: str = ''


def background(group):
    """Schedule on the UI event loop; never cancel an in-flight mutation."""
    def decorate(method):
        @wraps(method)
        def start(self, *args, **kwargs):
            existing = self.jobs.get(group)
            if existing and not existing.done():
                return existing
            async def invoke():
                try:
                    return await method(self, *args, **kwargs)
                except Exception as error:
                    self.say(error)
                finally:
                    self.dirty = True
            task = asyncio.create_task(invoke())
            self.jobs[group] = task
            return task
        return start
    return decorate

class SSHManager:
    """UI-independent workflows and table data shared by the curses frontend."""
    def __init__(self, config_path=None, data_dir=None, demo=False):
        self.demo = demo
        self.config = SSHConfig(config_path or Path.home()/".ssh"/"config")
        self.store = Store(data_dir or data_path())
        self.vault = Vault(self.store.directory)
        self.remote = Remote(self.config, self.sudo_password)
        self.hosts, self.key_rows, self.table_ids = [], [], []
        self.account_rows = {}
        self.pending_secure = set(self.store.setting('pending_secure',[]))
        self.expanded_keys = set()
        self.headers, self.rows = [], []
        self.selected_alias = ""
        self.view = "connections"
        self.filter_text = ""
        self.paused = self.busy = self.loading_config = False
        self.last_input = time.monotonic()
        self.last_probe = self.last_config_check = self.last_ping = 0
        self.pings = {}
        self.message = "Loading SSH configuration…"
        self.jobs = {}
        self.vault_open_lock = asyncio.Lock()
        self.ui = None
        self.is_running = True
        self.dirty = True
        self.cursor = 0
        self.selections = {}
        self.select_after_refresh = None
        self.render_table()

    def say(self, message):
        self.message = str(message)
        self.dirty = True

    def suspend(self):
        return self.ui.suspend() if self.ui else nullcontext()

    async def push_screen_wait(self, screen):
        if not self.ui:
            raise RuntimeError("This action needs the interactive terminal.")
        return await self.ui.show(screen)

    def exit(self):
        self.is_running = False

    def row_id(self):
        return self.table_ids[self.cursor] if 0 <= self.cursor < len(self.table_ids) else None

    def action_view(self, name):
        if self.busy or name not in VIEWS:
            return
        self.selections[self.view] = self.row_id()
        self.view = name
        self.filter_text = ""
        self.cursor = 0
        self.render_table(selected=self.selections.get(name))
        if name in ('vault','accounts') and not self.vault.cipher and not self.demo and not getattr(self.ui,"modal",None):
            self.open_password_store()

    @background("vault")
    async def open_password_store(self):
        await self.action_unlock.__wrapped__(self)

    def select(self, index):
        self.cursor = max(0, min(index, len(self.table_ids)-1))
        if self.view == "connections" and self.row_id() and self.row_id() != ADD_CONNECTION:
            self.selected_alias = self.row_id()
        self.dirty = True

    def action_lock(self):
        if self.busy:
            self.say("An operation is running; lock the vault after it finishes.")
            return
        self.vault.lock()
        if self.ui:
            self.ui.close_secret()
        self.say("Saved passwords hidden.")
        self.render_table()

    def tick(self):
        moment = time.monotonic()
        if self.vault.cipher and self.vault.protection not in ('application','keyring') and not self.busy and moment-self.last_input > 300:
            self.action_lock()
        if moment-self.last_config_check >= 5:
            self.last_config_check = moment
            self.refresh_inventory()
        if not self.paused and moment-self.last_ping>=2:
            self.ping_all()
        if not self.paused and not self.busy and moment-self.last_probe >= self.store.setting("interval", 30):
            self.probe_all()

    def set_secure_pending(self, alias, pending):
        if pending:self.pending_secure.add(alias)
        else:self.pending_secure.discard(alias)
        self.store.set_setting('pending_secure',sorted(self.pending_secure))

    def secure_pending(self, alias):
        return alias in self.pending_secure or self.store.get(alias).get('secure_setup',{}).get('status') in ('pending','running','stopped')

    def render_table(self, selected=None):
        selected_key = selected if selected is not None else self.row_id()
        cursor = self.cursor
        data = self.metadata()
        rows = []
        headers = []
        if self.view == "connections":
            headers = ["SSH ALIAS", "HOST / IP", "USER", "PORT", "PING", "STATUS"]
            for h in self.hosts:
                if self.secure_pending(h.alias):continue
                m = self.store.get(h.alias).get("monitoring", {})
                live=self.pings.get(h.alias,{})
                if live.get('signature')==h.signature:m=live
                monitored=self.store.get(h.alias).get('monitor',True)
                latency=str(m['latency'])+' ms' if monitored and m.get('status')=='ONLINE' and m.get('latency') is not None else '—'
                rows.append((h.alias,[h.alias,h.hostname,h.user,str(h.port),latency,m.get('status','UNKNOWN') if monitored else 'PAUSED']))
        elif self.view == "domains":
            headers = ["DOMAIN", "SOURCE", "CURRENT DNS", "ADDRESSES", "CHECKED (UTC)"]
            rows = [(d["name"], [d["name"], d.get("source", "Manual"), d.get("status", "UNCHECKED"), ", ".join(d.get("addresses", [])) or "—", d.get("checked", "—")]) for d in data.get("domains", [])]
        elif self.view == "users":
            headers = ["USER", "UID", "SHELL", "HOME", "AUTHORISED KEYS", "INSPECTED (UTC)"]
            rows = [(u["user"], [u["user"], str(u["uid"]) if u["uid"] is not None else "—", u["shell"] or "—", u["home"] or "—", str(len(u.get("keys", []))), (u.get("inspected", data.get("inspected")) or "—")]) for u in data.get("users", [])]
        elif self.view == "accounts":
            headers = ["KEY / USER", "SERVER", "DETAILS"]
            self.account_rows = {}
            for item in self.key_rows:
                path=item['path']
                deployments=self.key_attachments(item)
                self.account_rows[path]=dict(kind='key',item=item,deployments=sorted(deployments))
                rows.append((path,[Path(path).name,'',item['fingerprint']]))
            rows.append((ADD_KEY,['Generate New Key','','']))
            for h in self.hosts:
                meta=self.store.get(h.alias)
                users={u['user']:u for u in meta.get('users',[])}
                if h.user:
                    users.setdefault(h.user,dict(user=h.user))
                for name in sorted(users):
                    key='account:'+meta['id']+':'+name
                    self.account_rows[key]=dict(kind='account',alias=h.alias,user=name,server_id=meta['id'])
                    record=self.vault.records.get(f"{meta['id']}:{name}") if self.vault.cipher else None
                    password_status='Prepared password · check Activity' if record and record.get('notes','').startswith('Prepared for') else 'Enter to view password' if record else 'No saved password'
                    rows.append((key,[name,h.alias,password_status]))
        elif self.view == "keys":
            headers = ["LOCAL PUBLIC KEY", "FINGERPRINT", "LABEL", "OBSERVED ACCOUNTS"]
            for key in self.key_rows:
                deployments = []
                for h in self.hosts:
                    for u in self.store.get(h.alias).get("users", []):
                        if any(k["fingerprint"] == key["fingerprint"] for k in u.get("keys", [])):
                            deployments.append(f"{u['user']}@{h.alias}")
                rows.append((key["path"], [Path(key["path"]).name, key["fingerprint"], key["label"], ", ".join(deployments) or "Not inspected / not found"]))
        elif self.view == "vault":
            headers = ["USER", "PASSWORD", "UPDATED (UTC)"]
            if self.vault.cipher:
                rows = [(v["user"], [v["user"], "•••••••• · Enter to reveal", v["updated"]]) for v in self.vault.for_server(data.get("id", ""))]
        else:
            headers = ["TIME (UTC)", "SERVER", "ACTION", "RESULT"]
            rows = [(str(e["id"]), [e["at"], e["server"], e["action"], e["result"].replace("\n", " ")]) for e in self.store.events()]
        self.headers = headers
        self.rows = [(key, [str(c) for c in cells]) for key, cells in rows if self.filter_text.casefold() in " ".join(str(c) for c in cells).casefold()]
        if self.view == "connections":
            self.rows.append((ADD_CONNECTION, ['+ Add Connection']+['']*(len(headers)-1)))
        if self.view=='accounts':
            filtered=self.rows
            self.rows=[]
            self.rows.extend((key,cells) for key,cells in filtered if self.account_rows.get(key,{}).get('kind')=='key')
            self.rows.append((ADD_KEY,['Generate New Key','','']))
            self.rows.append((IMPORT_KEY,['Import Key','','']))
            self.rows.extend((key,cells) for key,cells in filtered if self.account_rows.get(key,{}).get('kind')=='account')
        self.table_ids = [key for key, _ in self.rows]
        target = selected if selected is not None else self.selected_alias if self.view == "connections" and selected_key != ADD_CONNECTION else selected_key
        self.cursor = self.table_ids.index(target) if target in self.table_ids else max(0, min(cursor, len(self.table_ids)-1))
        if self.view == "connections" and self.row_id() and self.row_id() != ADD_CONNECTION:
            self.selected_alias = self.row_id()
        self.dirty = True

    def host(self):
        return next((h for h in self.hosts if h.alias == self.selected_alias), None)

    def metadata(self):
        return self.store.get(self.selected_alias)

    def sudo_password(self, host):
        if not self.vault.cipher:
            return ''
        ident = self.store.get(host.alias).get('id', '')
        return self.vault.records.get(f'{ident}:{host.user}', {}).get('password', '')

    @background("config")
    async def refresh_inventory(self, force=False):
        if self.demo or self.busy or self.loading_config or (not force and not self.config.needs_refresh()):
            return
        self.loading_config = True
        try:
            hosts = await asyncio.to_thread(self.config.discover)
            first_load = not self.hosts
            self.hosts = hosts
            self.store.reconcile(hosts)
            self.key_rows = await asyncio.to_thread(self.scan_keys)
            if not any(h.alias == self.selected_alias for h in hosts):
                self.selected_alias = hosts[0].alias if hosts else ""
            self.render_table(selected=self.select_after_refresh or (self.selected_alias if first_load else None))
            self.select_after_refresh = None
            self.say(f"Loaded {len(hosts)} SSH connections · {len(self.store.archive())} archived records · config sync active" + (" · "+"; ".join(self.config.warnings) if self.config.warnings else ""))
            self.last_probe = 0
        except Exception as error:
            self.say(error)
        finally:
            self.loading_config = False

    @background("monitor")
    async def probe_all(self):
        if self.demo or self.busy:
            return
        self.last_probe = time.monotonic()
        targets = [h for h in self.hosts if self.store.get(h.alias).get("monitor", True) and not self.secure_pending(h.alias)]
        semaphore = asyncio.Semaphore(8)
        async def one(h):
            async with semaphore:
                result = await asyncio.to_thread(check, h)
                previous = self.store.get(h.alias).get("monitoring", {})
                if "addresses" in result and previous.get("addresses") is not None and result["addresses"] != previous["addresses"]:
                    self.store.audit(h.alias, "Resolved IPs changed", ", ".join(previous["addresses"])+" → "+", ".join(result["addresses"]))
                if previous.get("status") != result["status"]:
                    result["changed"] = now()
                    self.store.audit(h.alias, "Reachability", result["status"])
                else:
                    result["changed"] = previous.get("changed", now())
                if "addresses" not in result:
                    result["addresses"] = previous.get("addresses", [])
                    result["public_ips"] = previous.get("public_ips", [])
                self.store.update(h.alias, monitoring=result)
        await asyncio.gather(*(one(h) for h in targets))
        if self.is_running:
            self.render_table()

    @background('ping')
    async def ping_all(self):
        if self.demo:return
        self.last_ping=time.monotonic()
        semaphore=asyncio.Semaphore(8)
        targets=[h for h in self.hosts if self.store.get(h.alias).get('monitor',True) and not self.secure_pending(h.alias)]
        async def one(host):
            async with semaphore:
                result=await asyncio.to_thread(ping,host)
                # Ignore responses for connections edited while the probe was running.
                if any(h.alias==host.alias and h.signature==host.signature for h in self.hosts):
                    self.pings[host.alias]=dict(signature=host.signature,**result)
                    self.render_table()
        await asyncio.gather(*(one(host) for host in targets))
        current={host.alias for host in self.hosts}
        self.pings={alias:value for alias,value in self.pings.items() if alias in current}

    def default_key(self, alias='', hostname='', user=''):
        from .config import Host
        from .key_import import matching_public_key
        probe=Host(alias or 'ssh-manager-new',self.config.path,0,0,[alias or 'ssh-manager-new'],'')
        config=self.config if self.config.path.exists() else SSHConfig(Path(os.devnull))
        inherited=config.resolve(probe)
        for candidate in inherited.identities:
            for token,value in (('%d',str(Path.home())),('%h',hostname or inherited.hostname),('%r',user or inherited.user),('%n',probe.alias)):
                candidate=candidate.replace(token,value)
            path=Path(candidate).expanduser()
            if matching_public_key(path):return str(path.resolve())
        return ''

    def scan_keys(self):
        extra = []
        for host in self.hosts:
            for value in host.identities:
                for token, replacement in (("%d", str(Path.home())), ("%h", host.hostname), ("%r", host.user), ("%n", host.alias)):
                    value = value.replace(token, replacement)
                extra.append(value)
        return local_keys(self.config.path.parent, extra)

    @background("interaction")
    async def action_open(self):
        if self.demo:
            self.say("Demo mode: actions are disabled.")
            return
        if self.view=='vault' and not self.vault.cipher:
            await self.action_unlock.__wrapped__(self)
            return
        key = self.row_id()
        host = self.host()
        if self.view=='accounts':
            if key==ADD_KEY:
                await self.action_new_key.__wrapped__(self)
            elif key==IMPORT_KEY:
                await self.action_import_key.__wrapped__(self)
            elif self.account_rows.get(key,{}).get('kind')=='key':
                self.toggle_key_details()
            elif key in self.account_rows:
                account=self.account_rows[key]
                if not self.vault.cipher and not await self.action_unlock.__wrapped__(self):
                    return
                record=self.vault.records.get(f"{account['server_id']}:{account['user']}")
                if record:
                    self.store.audit(account['alias'],'Vault reveal',account['user'])
                    await self.push_screen_wait(Viewer(f"{account['user']}@{account['alias']}",record['password'],secret=True,compact=True))
                else:
                    await self.push_screen_wait(Viewer('No saved password','No password is saved for this account. Existing server passwords cannot be retrieved.',compact=True))
        elif self.view == "connections" and key == ADD_CONNECTION:
            await self.action_add.__wrapped__(self)
        elif self.view == "connections" and host:
            self.store.audit(host.alias, "SSH session", "Opened interactive connection")
            with self.suspend():
                result = subprocess.run(["ssh", "-F", str(self.config.path), "--", host.alias])
            self.say(f"Returned from {host.alias} · SSH exit {result.returncode}")
        elif key and self.view == "users":
            user = next(u for u in self.metadata().get("users", []) if u["user"] == key)
            await self.push_screen_wait(Viewer(f"{key}@{self.selected_alias} · authorised keys", json.dumps(user, indent=2)))
        elif key and self.view == "keys":
            item = next(k for k in self.key_rows if k["path"] == key)
            await self.push_screen_wait(Viewer("Public key · "+item["label"], item["public_key"]+"\n\n"+item["fingerprint"]+"\n"+item["path"]))
        elif key and self.view == "vault" and self.vault.cipher:
            record = next(v for v in self.vault.for_server(self.metadata()["id"]) if v["user"] == key)
            self.store.audit(self.selected_alias, "Vault reveal", key)
            await self.push_screen_wait(Viewer(f"{key}@{self.selected_alias} · password", record["password"]+"\n\n"+record["notes"], secret=True))
        elif key and self.view == "domains":
            item = next(d for d in self.metadata().get("domains", []) if d["name"] == key)
            await self.push_screen_wait(Viewer("Domain details", json.dumps(item, indent=2)))
        elif key and self.view == "activity":
            item = next(e for e in self.store.events() if str(e["id"]) == key)
            await self.push_screen_wait(Viewer("Activity", json.dumps(item, indent=2)))

    async def form(self, title, fields, help_text="", submit="Save", delete=False, error=""):
        return await self.push_screen_wait(Form(title, fields, help_text, submit, delete, error=error))

    async def confirm(self, title, explanation, phrase):
        result = await self.form(title, [("confirm", f"Type {phrase} to continue", "", False)], explanation, "Confirm")
        if not result:
            return False
        if result["confirm"] != phrase:
            self.say("Confirmation did not match; cancelled.")
            return False
        return True

    def require_host(self):
        if self.view=='accounts':
            alias=self.account_rows.get(self.row_id(),{}).get('alias')
            host=next((h for h in self.hosts if h.alias==alias),None)
        elif self.view=='connections':
            host=None if self.row_id()==ADD_CONNECTION else self.host()
        else:
            host=None
        if not host:
            self.say('Select an account or choose a connection for this action.')
        return host

    async def choose_action_host(self):
        if self.view=='accounts':
            account=self.account_rows.get(self.row_id(),{})
            if account.get('kind')=='account':
                return next((h for h in self.hosts if h.alias==account['alias']),None)
            if not self.hosts:
                self.say('Add a connection first.')
                return None
            result=await self.push_screen_wait(Form('Choose server',[
                ('server','Server',self.hosts[0].alias,False)],
                'Choose the server for this action.','Continue',choices={'server':[h.alias for h in self.hosts]}))
            return next((h for h in self.hosts if h.alias==result['server']),None) if result else None
        return self.require_host()

    @background("interaction")
    async def action_add(self):
        if self.demo:
            return
        try:
            if self.view == "connections":
                await self.connection_form()
            elif self.view == "domains" and self.require_host():
                result = await self.form("Add domain · "+self.selected_alias, [("domain", "Domain name", "", False)])
                if result:
                    name = valid_domain(result["domain"])
                    domains = self.metadata().get("domains", [])
                    if not any(d["name"] == name for d in domains):
                        domains.append({"name": name, "source": "Manual"})
                        self.store.update(self.selected_alias, domains=domains)
                        self.store.audit(self.selected_alias, "Domain added", name)
                    self.render_table()
                    self.verify_dns()
            elif self.view == "vault" and self.require_host():
                if not self.vault.cipher and not await self.action_unlock.__wrapped__(self):
                    return
                result = await self.form("Save password · "+self.selected_alias, [("user", "Server username", self.host().user, False), ("password", "Password", "", True), ("notes", "Notes", "", False)])
                if result:
                    if not result["user"] or not result["password"]:
                        raise ValueError("Username and password are required.")
                    self.vault.put(self.metadata()["id"], result["user"], result["password"], result["notes"])
                    self.store.audit(self.selected_alias, "Vault save", result["user"])
                    self.say("Password encrypted and saved.")
                    self.render_table()
            elif self.view == "keys":
                await self.action_new_key.__wrapped__(self)
            else:
                self.say("Use o for remote administration, or a in Connections / Domains / Vault.")
        except Exception as error:
            self.say(error)
            if self.view == "connections":
                await self.push_screen_wait(Viewer("Connection could not be added", str(error)))

    async def connection_form(self, host=None):
        initial = None
        while True:
            try:
                retry = await self._connection_form_attempt(host, initial)
            finally:
                if initial:
                    initial.clear()
            if not isinstance(retry, dict):
                return
            initial = retry

    async def _connection_form_attempt(self, host=None, initial=None):
        initial = initial or {}
        identities = self.config.explicit_identities(host) if host else []
        if len(identities) > 1:
            raise ValueError("This connection has multiple identity files. Use Shift+X to edit its config without removing them.")
        fields = [
            ("alias", "SSH alias", host.alias if host else "", False),
            ("hostname", "Hostname / IP", host.hostname if host else "", False),
            ("port", "Port", str(host.port) if host else "22", False),
            ("user", "SSH Username", host.user if host else "", False),
            ("identity", "SSH Key (leave blank for default)", identities[0] if identities else "", False),
        ]
        fields = [(key,label,initial.get(key,value),secret) for key,label,value,secret in fields]
        if host:
            result = await self.form("Edit SSH connection", fields, "Backups are made before edits. Shift+X opens the original configuration.", delete=True, error=initial.get("_error", ""))
        else:
            default_key=await asyncio.to_thread(self.default_key,initial.get('alias',''),initial.get('hostname',''),initial.get('user',''))
            secure_fields = [
                ('login_password','Current Password (leave blank to use key)','',True),
                ('block_bootstrap','Disable this user and add new SSH user account','yes',False),
                ('new_user','Username','',False),
                ('new_password','Password (leave blank to generate random password)','',True),
                ('new_identity',"SSH Key",default_key,False),
                ('sudo_mode','New account sudo policy','passwordless',False),
                ('key_only','Set SSH Server to Key login only','yes',False),
                ('new_port','Set new SSH port','',False),
            ]
            secure_fields = [(key,label,initial.get(key,value),secret) for key,label,value,secret in secure_fields]
            choices={key:['yes','no'] for key in ('block_bootstrap','key_only')}
            choices['sudo_mode']=['passwordless','password required']
            result = await self.push_screen_wait(Form('Add Connection', fields, '', 'Add', tabs=True, secure_tab=bool(initial.get('_secure')), secure_fields=secure_fields, choices=choices, sections={'alias':'Connection Details','user':'Current Credentials','new_user':'New Secure Account','key_only':'Security Settings'}, existing_sections={'alias':'Existing Server'}, key_pickers={'identity','new_identity'}, placeholders={'new_identity':'No default key found; Enter to choose'}, conditional_hide=('block_bootstrap','no',{'new_user','new_identity','new_password','sudo_mode'}), error=initial.get('_error','')))
        if not result:
            return
        saved = False
        try:
            if result.get('_action') == 'delete' and host:
                if not await self.delete_connection(host):
                    return result.copy()
                return
            secure = bool(result.get('_secure'))
            plan = None
            if secure:
                replace_account = result.get('block_bootstrap','yes') == 'yes'
                import re
                import secrets
                from .secure import Setup, generate_account_password
                name = result.get('new_user','').strip() if replace_account else result['user'].strip()
                if replace_account and (not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',name) or name=='root' or name==result['user'].strip()):
                    raise ValueError('Choose a new normal username, different from the initial administrator.')
                if not result['user'].strip():
                    raise ValueError('Enter the initial administrator username, usually root.')
                port_value = result.get('new_port','').strip()
                try:
                    new_port = int(port_value) if port_value else None
                except ValueError:
                    raise ValueError('Enter a New SSH Port between 1 and 65535, or leave it blank.') from None
                if new_port is not None and not 1 <= new_port <= 65535:
                    raise ValueError('New SSH Port must be between 1 and 65535.')
                if new_port == int(result.get('port') or 22):
                    new_port = None
                key_value = result.get('new_identity','').strip() if replace_account else result.get('identity','').strip()
                recovery = (result.get('new_password','') or generate_account_password()) if replace_account else result.get('login_password','')
                if replace_account and ((len(recovery)<16 and not re.fullmatch(r'[a-z0-9]{6}-[a-z0-9]{6}',recovery)) or any(c in recovery for c in '\r\n')):
                    raise ValueError('Use at least 16 characters for the account password, or leave it blank to generate one.')
                if not self.vault.cipher:
                    await self.action_unlock.__wrapped__(self)
                if not self.vault.cipher:
                    return result.copy()
                if key_value.lower() == 'new':
                    alias_label = re.sub(r'[^A-Za-z0-9_.-]', '_', result['alias'])[:40] or 'server'
                    keypath = self.config.path.parent / 'keys' / f'{alias_label}-{name}-ed25519-{secrets.token_hex(4)}'
                    with self.suspend():
                        create_key(keypath, f'{name}@{result["alias"]} · ssh-manager')
                        # A passphrase-protected new key must be available to the
                        # fresh, noninteractive verification connection.
                        readable = subprocess.run(['ssh-keygen','-y','-P','','-f',str(keypath)],capture_output=True,text=True,timeout=5)
                        if readable.returncode:
                            loaded = subprocess.run(['ssh-add',str(keypath)])
                            if loaded.returncode:
                                raise ValueError(f'Key saved at {keypath}. Load it into ssh-agent, then retry using this path.')
                    self.store.audit('local','Key created',str(keypath))
                else:
                    if not key_value:
                        key_value=await asyncio.to_thread(self.default_key,result['alias'],result['hostname'],result['user'])
                    keypath = Path(key_value).expanduser().resolve()
                if not keypath.is_file():
                    raise ValueError("Select a private key with a matching .pub file, or type 'new' to generate a key pair.")
                public = self.read_public_key(str(keypath)+'.pub')
                prior=self.store.get(result['alias']).get('secure_setup',{})
                resume_id=prior.get('id','') if prior.get('status')=='stopped' and prior.get('user')==name else ''
                plan = Setup(name,str(keypath),public,recovery,result.get('login_password',''),passwordless=result.get('sudo_mode')=='passwordless' if replace_account else True,new_port=new_port,reuse_existing=not replace_account,resume_setup_id=resume_id,bootstrap_key=result.get('identity','').strip(),generated_password=replace_account and (not result.get('new_password') or bool(initial.get('_generated_password') and result.get('new_password')==initial.get('new_password'))),lock_root=False,**{key:result.get(key)=='yes' for key in ('block_bootstrap','key_only')})
            retry_values=result.copy()
            if secure:
                retry_values['new_identity']=plan.keypath
                if not plan.reuse_existing:
                    retry_values['new_password']=plan.recovery_password
                    retry_values['_generated_password']=plan.generated_password
            if secure and plan.bootstrap_key:
                result['identity']=plan.keypath
            if secure:self.set_secure_pending(result['alias'],True)
            alias = await asyncio.to_thread(self.config.save, result, host)
            saved = True
            if host and host.alias != alias:
                self.store.rename(host.alias, alias)
            self.selected_alias = alias
            self.select_after_refresh = alias
            self.store.audit(alias, 'SSH config', 'Updated' if host else 'Added')
            if secure:
                completed=await self.secure_connection(alias,plan)
                if completed is False and host is None:
                    current=await asyncio.to_thread(self.config.discover)
                    provisional=next((entry for entry in current if entry.alias==alias),None)
                    if provisional:await asyncio.to_thread(self.config.remove,provisional)
                    self.set_secure_pending(alias,False)
                    await self.refresh_inventory(force=True)
                    self.say('Returned to connection details.')
                    return retry_values
            else:
                self.set_secure_pending(alias,False)
                if self.store.get(alias).get('secure_setup'):
                    self.store.update(alias,secure_setup={})
                self.refresh_inventory(force=True)
        except Exception as error:
            if not saved:self.set_secure_pending(result.get('alias',''),False)
            if saved:
                raise
            retry = result.copy()
            retry['_error'] = str(error)
            return retry
        finally:
            result.clear()

    async def secure_connection(self, alias, plan):
        from .secure import SecureTransport, provision
        hosts = await asyncio.to_thread(self.config.discover)
        self.hosts = hosts
        self.store.reconcile(hosts)
        host = next(h for h in hosts if h.alias==alias)
        self.set_secure_pending(alias,True)
        self.store.update(alias,secure_setup=dict(id=plan.setup_id,user=plan.new_user,status='pending'))
        if host.error or host.proxy:
            raise ValueError('Secure setup currently requires a direct SSH connection with valid settings.')
        self.render_table(selected=alias)
        transport = SecureTransport(self.config,host,plan)
        choices = f"{'New user' if not plan.reuse_existing else 'Keep current account'}: {plan.new_user}\nSudo: {'existing policy' if plan.reuse_existing else 'passwordless' if plan.passwordless else 'password required'}\nDisable ({host.user}) SSH access: {'Yes' if plan.block_bootstrap else 'No'}\nKey-only SSH: {plan.key_only}"
        if plan.new_port and plan.new_port != host.port:
            choices += f"\nSSH port: {host.port} → {plan.new_port}"
        review = f"Server: {host.user}@{host.hostname}\n{choices}\nWill install sudo if not present · console accounts retained\nBackups + five-minute SSH rollback · passwords saved in Vault" + ('\nAllow the new port in your VM/provider firewall before continuing.' if plan.new_port else '')
        if plan.generated_password:
            review+='\nGenerated password: '+plan.recovery_password
        while True:
            if await self.push_screen_wait(Form('Review new server setup',[],review,'Yes',overview=True,highlights={'Allow the new port in your VM/provider firewall before continuing.':2})) is None:
                return False
            if plan.new_port and plan.new_port!=host.port:
                warning='YOU ARE CHANGING THE SSH PORT ON THIS SERVER. PLEASE CONFIRM THE NEW PORT IS ALLOWED THROUGH THE FIREWALL'
                if await self.push_screen_wait(Form('Confirm new SSH port firewall rule',[],warning,'Continue',overview=True,default_cancel=True,text_colour=2)) is None:
                    continue
            break
        # Save recovery material before the server account is created.
        ident=self.store.get(alias)['id']
        if plan.recovery_password:
            self.vault.put(ident,plan.new_user,plan.recovery_password,'Prepared for secure onboarding; check Activity for completion.')
        if plan.bootstrap_password:
            self.vault.put(ident,host.user,plan.bootstrap_password,'Initial administrator credential; SSH may be restricted after setup.')
        self.setup_stage=0
        self.setup_stages=7 if plan.new_port else 6
        self.busy = self.secure_setup_running = True
        completed = False
        self.store.update(alias,secure_setup=dict(id=plan.setup_id,user=plan.new_user,status='running'))
        def audit(action, outcome):self.store.audit(alias,action,outcome)
        async def save_config():
            # Preserve an outside edit rather than silently overwriting it.
            values=dict(alias=alias,hostname=host.hostname,user=plan.new_user,port=str(plan.new_port or host.port),identity=plan.keypath)
            if plan.new_port:
                values['hostkeyalias']=transport.host_key_alias
            await asyncio.to_thread(self.config.save,values,host)
        try:
            self.setup_stage=0
            self.setup_stages=7 if plan.new_port else 6
            def progress(message):
                self.setup_stage+=1
                self.say(message)
            def recovery(error,seconds):
                self.setup_error=error
                self.setup_countdown=seconds
                self.dirty=True
            result=await provision(transport,save_config,audit,progress,recovery)
            completed=True
            if plan.recovery_password:
                self.vault.put(ident,plan.new_user,plan.recovery_password,'Secure setup completed. '+('Existing sudo policy preserved.' if plan.reuse_existing else 'Passwordless sudo.' if plan.passwordless else 'Use this password for sudo.'))
                self.store.record_account_password(alias,plan.new_user)
            self.store.update(alias,secure_setup=dict(id=plan.setup_id,user=plan.new_user,status='complete',backup=result.get('backup','')))
        except Exception as error:
            if completed:
                audit('Setup complete; local update failed',str(error))
                await self.push_screen_wait(Viewer('Server setup completed', 'The server setup committed successfully, but a local record update failed: '+str(error)))
            else:
                audit('Secure setup stopped',str(error))
                self.store.update(alias,secure_setup=dict(id=plan.setup_id,user=plan.new_user,status='stopped'))
                await self.push_screen_wait(Viewer('Secure setup stopped',str(error)+'\n\nExisting accounts and any new account are retained. If SSH restrictions were applied, recovery was requested; the server-side five-minute timer also attempts to restore SSH access. Check Activity. Passwords remain in Vault.',compact=True))
        finally:
            plan.bootstrap_password=''
            self.setup_error=''
            self.setup_countdown=None
            self.busy=self.secure_setup_running=False
            await self.refresh_inventory(force=True)
            if completed:
                self.set_secure_pending(alias,False)
                self.render_table(selected=alias)
        if completed:
            if not plan.passwordless and not plan.reuse_existing:
                await self.push_screen_wait(Viewer('New account sudo password',plan.recovery_password,secret=True))
            plan.recovery_password=''
            choice = await self.push_screen_wait(Form('Server ready',[],f'{plan.new_user}@{alias} is ready. Login and sudo verified.','Connect',overview=True,cancel='Close'))
            if choice is not None:
                await self.action_open.__wrapped__(self)
        return completed


    @background("interaction")
    async def action_edit(self):
        if self.demo:
            return
        try:
            if self.view == "connections" and self.require_host():
                await self.connection_form(self.host())
            elif self.view == "vault":
                await self.action_add.__wrapped__(self)
            else:
                self.say("Press n for server notes, or use a / d to manage domains.")
        except Exception as error:
            self.say(error)

    @background("interaction")
    async def action_delete(self):
        if self.demo:
            return
        if self.view=='accounts':
            if self.account_rows.get(self.row_id(),{}).get('kind')=='key':
                await self.delete_local_key(self.account_rows[self.row_id()]['item'])
            return
        key, host = self.row_id(), self.require_host()
        if not key or not host:
            return
        try:
            if self.view == "connections":
                await self.delete_connection(host)
            elif self.view == "domains":
                if await self.confirm("Remove domain", f"Remove {key} from this local inventory?", key):
                    self.store.update(host.alias, domains=[d for d in self.metadata().get("domains", []) if d["name"] != key])
                    self.store.audit(host.alias, "Domain removed", key)
                    self.render_table()
            elif self.view == "vault" and self.vault.cipher:
                if await self.confirm("Remove saved password", f"Delete the saved password for {key}@{host.alias}? This does not change the server password.", key):
                    self.vault.records.pop(f"{self.metadata()['id']}:{key}", None)
                    self.vault.save()
                    self.store.audit(host.alias, "Vault delete", key)
                    self.render_table()
            else:
                self.say("Use o for remote account or authorised-key removal.")
        except Exception as error:
            self.say(error)

    def key_attachments(self, item):
        fingerprint=item['fingerprint']
        paths={Path(k['path']).expanduser().with_suffix('').resolve() for k in self.key_rows if k['fingerprint']==fingerprint}
        paths.add(Path(item['path']).expanduser().with_suffix('').resolve())
        deployments=set()
        for host in self.hosts:
            for user in self.store.get(host.alias).get('users',[]):
                if any(k.get('fingerprint')==fingerprint for k in user.get('keys',[])):
                    deployments.add(f"{user['user']}@{host.alias} (observed)")
            for identity in host.identities:
                for token,value in (('%d',str(Path.home())),('%h',host.hostname),('%r',host.user),('%n',host.alias)):
                    identity=identity.replace(token,value)
                path=Path(identity).expanduser()
                if path.suffix=='.pub':path=path.with_suffix('')
                if path.resolve() in paths:
                    deployments.add(f'{host.user}@{host.alias} (SSH config)')
        return deployments

    async def delete_local_key(self, item):
        async def check_attached():
            self.hosts=await asyncio.to_thread(self.config.discover)
            if any(host.error for host in self.hosts):
                raise ValueError('Cannot verify key attachments while an SSH connection has a configuration error.')
            self.key_rows=await asyncio.to_thread(self.scan_keys)
            attached=self.key_attachments(item)
            if attached:
                raise ValueError('Delete all attached server connections before deleting this key: '+', '.join(sorted(attached)))
        try:
            await check_attached()
        except Exception as error:
            await self.push_screen_wait(Viewer('Key cannot be deleted',str(error),compact=True))
            return
        async def remove(values):
            self.busy=True
            try:
                await check_attached()
                from .key_deletion import remove_key_files
                recovery=await asyncio.to_thread(remove_key_files,item['path'],item['fingerprint'],self.store.directory)
                self.expanded_keys.discard(item['path'])
                self.key_rows=await asyncio.to_thread(self.scan_keys)
                self.store.audit('local','Key deleted',Path(item['path']).name+' · recovery: '+str(recovery))
                self.render_table()
            finally:
                self.busy=False
        result=await self.push_screen_wait(Form('Delete SSH key',[],
            'Delete '+Path(item['path']).name+' and its private key from this computer? A local recovery copy is retained. No active server attachments were found.',
            'Delete',overview=True,default_cancel=True,submit_handler=remove,submit_status='Checking attachments and deleting key…'))
        if result is not None:
            result.clear()
            self.say('Key removed from the local list.')

    async def delete_connection(self, host):
        result=await self.push_screen_wait(Form("Delete connection",[],f"Delete {host.alias} from your SSH configuration? Server accounts are unaffected. Inventory and saved passwords will be archived.","Delete",overview=True,default_cancel=True))
        if result is not None:
            await asyncio.to_thread(self.config.remove, host)
            self.store.audit(host.alias, "SSH config", "Removed; inventory archived")
            self.refresh_inventory(force=True)
            return True
        return False

    @background("interaction")
    async def action_notes(self):
        if self.demo or self.view!="connections" or not self.require_host():
            return
        data = self.metadata()
        result = await self.form("Server details · "+self.selected_alias, [("notes", "Notes (keep passwords in Vault)", data.get("notes", ""), False), ("tags", "Tags (comma separated)", data.get("tags", ""), False), ("public", "Additional known public IPs (comma separated; e.g. NAT)", ", ".join(data.get("manual_public_ips", [])), False), ("monitor", "Monitor this server? yes / no", "yes" if data.get("monitor", True) else "no", False)])
        if result:
            try:
                import ipaddress
                ips = [str(ipaddress.ip_address(value.strip())) for value in result["public"].split(",") if value.strip()]
                if any(not ipaddress.ip_address(value).is_global for value in ips):
                    raise ValueError("Additional public IPs must be globally routable addresses.")
            except ValueError as error:
                self.say(error)
                return
            self.store.update(self.selected_alias, notes=result["notes"], tags=result["tags"], manual_public_ips=ips, monitor=result["monitor"].strip().lower() != "no")
            self.render_table()
            self.say("Server details saved.")

    def action_refresh(self):
        if self.demo:
            return
        if self.view == "domains":
            self.verify_dns()
        else:
            self.refresh_inventory(force=True)
            if not self.paused:
                self.probe_all()

    @background("dns")
    async def verify_dns(self):
        host = self.require_host()
        if not host or self.demo:
            return
        alias = host.alias
        try:
            self.say("Checking PTR and current A/AAAA records…")
            data = self.store.get(alias)
            ips = sorted(set(data.get("monitoring", {}).get("public_ips", []) + data.get("interface_public_ips", []) + data.get("manual_public_ips", [])))
            discovered = await asyncio.to_thread(reverse, ips)
            domains = {d["name"]: d for d in data.get("domains", [])}
            for item in discovered:
                domains.setdefault(item["name"], item)
            result = await asyncio.to_thread(verify_domains, list(domains.values()), ips)
            self.store.update(alias, domains=result)
            self.store.audit(alias, "DNS verification", f"{len(result)} domains; {len(ips)} known public IPs")
            self.render_table()
            self.say(f"{alias}: checked {len(result)} domains. PTR does not list every hosted domain.")
        except Exception as error:
            self.say(error)

    def action_pause(self):
        self.paused = not self.paused
        self.say("Monitoring paused." if self.paused else "Monitoring resumed.")
        self.render_table()

    @background("interaction")
    async def action_settings(self):
        result = await self.form("Monitoring settings", [("interval", "Check interval in seconds (10–3600)", str(self.store.setting("interval", 30)), False)], "Checks run only while the app is open. They check TCP reachability, not SSH authentication. Proxy routes are labelled separately.")
        if result:
            try:
                value = int(result["interval"])
                if not 10 <= value <= 3600:
                    raise ValueError("Choose an interval between 10 and 3600 seconds.")
                self.store.set_setting("interval", value)
                self.render_table()
            except ValueError as error:
                self.say(error)

    @background("interaction")
    async def action_unlock(self):
        async with self.vault_open_lock:
            return await self._open_password_store()

    async def _open_password_store(self):
        if self.demo:
            return False
        if self.vault.cipher:
            return True
        try:
            await asyncio.to_thread(self.vault.open_automatic)
        except LegacyVaultPasswordRequired:
            async def migrate(values):
                await asyncio.to_thread(self.vault.migrate_to_automatic,values['password'])
            result=await self.push_screen_wait(Form('Convert existing vault · once only',[('password','Old master password','',True)],'This older vault needs its existing password once. It will then open using your OS credential store. A recovery copy is encrypted with the new key and verified.','Convert',submit_handler=migrate,submit_status='Converting saved passwords…'))
            if result is None:
                return False
            result.clear()
        except Exception as error:
            async def retry(values):
                await asyncio.to_thread(self.vault.open_automatic)
            result=await self.push_screen_wait(Form('Open saved passwords',[],'Saved passwords open automatically. Resolve the error below and retry.','Retry',submit_handler=retry,submit_status='Opening saved passwords…',error=str(error)))
            if result is None:
                return False
            result.clear()
        self.last_input=time.monotonic()
        self.say('Saved passwords ready · no master password required.')
        self.render_table()
        return True

    def toggle_key_details(self, expanded=None):
        key=self.row_id()
        if self.account_rows.get(key,{}).get('kind')!='key':
            return
        show=key not in self.expanded_keys if expanded is None else expanded
        if show:self.expanded_keys.add(key)
        else:self.expanded_keys.discard(key)
        self.dirty=True

    @background("interaction")
    async def action_import_key(self):
        if self.demo:return
        return await self.import_key_dialog()

    async def import_key_dialog(self, show=None):
        show=show or self.push_screen_wait
        directory=Path.home()
        while True:
            imported=None
            source=await show(FileBrowser(directory=directory,title='Import Key · browse files',description='Select an SSH private key.',excluded_suffixes=('.pub',)))
            if source is None:return
            source=Path(source)
            directory=source.parent
            from .key_import import import_key
            async def copy(values):
                nonlocal imported
                public=await asyncio.to_thread(import_key,source,self.config.path.parent,values['filename'],values['passphrase'])
                self.store.audit('local','Key imported',public)
                self.key_rows=await asyncio.to_thread(self.scan_keys)
                self.render_table(selected=public)
                imported=str(Path(public).with_suffix(''))
            result=await show(Form('Import Key',[
                ('filename','Key',source.name.removesuffix('.pub'),False),
                ('passphrase','Key Passphrase','',True)],
                f'Copy into {self.config.path.parent}. Private keys only. Matching public keys are verified or derived. Originals are retained.',
                'Import',submit_handler=copy,submit_status='Validating and importing key…'))
            if result is not None:
                result.clear()
                self.say('Key imported. Original file retained.')
                return imported

    @background("interaction")
    async def action_new_key(self):
        if self.demo:
            return
        result=await self.new_key_dialog()
        if result is not None:result.clear()

    async def new_key_dialog(self, defer=False):
        generated={}
        async def generate(values):
            filename=values['path'].strip()
            if not filename or Path(filename).name=='id_ed25519_':
                raise ValueError('Enter a name after id_ed25519_.')
            keypath=Path(filename).expanduser()
            if not keypath.is_absolute():
                keypath=self.config.path.parent/keypath
            if os.path.lexists(keypath) or os.path.lexists(str(keypath)+'.pub'):
                raise ValueError('This key filename already exists. Choose another name; nothing was overwritten.')
            if any(c in values['label'] for c in '\r\n') or any(c in values['passphrase'] for c in '\r\n\x00'):
                raise ValueError('Key comment and passphrase must be single lines.')
            generated.update(path=str(keypath),passphrase=values['passphrase'],label=values['label'])
            if not defer:
                await asyncio.to_thread(create_key,str(keypath),values['label'],values['passphrase'])
                self.store.audit('local','Key created',str(keypath))
                self.key_rows=await asyncio.to_thread(self.scan_keys)
                self.render_table()
        result=await self.push_screen_wait(Form('Replacement key details' if defer else 'Create Ed25519 key',[
            ('path','Filename','id_ed25519_',False),
            ('label','Key Comment',f'{getpass.getuser()}@{socket.gethostname()}',False),
            ('passphrase','Passphrase (leave blank for none)','',True)],
            f'Keys are saved in {self.config.path.parent}. Add a name after the underscore. Existing files are never overwritten.',
            'Continue' if defer else 'Create',submit_handler=generate,submit_status='Checking key details…' if defer else 'Generating key pair…'))
        if result is not None:
            result.clear()
            if not defer:self.say('Key created. Use Admin to authorise it on a server.')
            return generated

    @background("interaction")
    async def action_editor(self):
        if self.demo:
            return
        path = self.host().source if self.host() else self.config.path
        editor = shlex.split(os.environ.get("VISUAL") or os.environ.get("EDITOR") or ("notepad" if os.name == "nt" else "nano"))
        try:
            if path.exists():
                self.config.backup(path)
            with self.suspend():
                subprocess.run([*editor, str(path)])
            self.refresh_inventory(force=True)
        except Exception as error:
            self.say(error)

    def action_inspect(self):
        if not self.demo:
            self.inspect_selected()

    @background("remote")
    async def inspect_selected(self, host=None):
        host = host or await self.choose_action_host()
        if not host:
            return
        if self.vault.path.exists() and not self.vault.cipher and not await self.action_unlock.__wrapped__(self):
            return
        self.busy = True
        try:
            self.say(f"Inspecting {host.alias} over SSH…")
            await self.inspect_host(host)
            self.render_table()
            self.say(f"{host.alias}: users, keys, interface public IPs and web domains inspected.")
        except Exception as error:
            self.store.audit(host.alias, "Inspection failed", str(error))
            self.say(error)
        finally:
            self.busy = False

    async def inspect_host(self, host):
        result = await asyncio.to_thread(self.remote.run, host, "inspect")
        old = self.store.get(host.alias)
        recorded = {u['user']: u for u in old.get('users', [])}
        for account in result.get('users', []):
            previous = recorded.get(account['user'], {})
            for field in ('password_ref','credential_updated'):
                if field in previous:
                    account[field] = previous[field]
        domains = {d["name"]: d for d in old.get("domains", [])}
        for name in result.pop("domains", []):
            domains.setdefault(name, {"name": name, "source": "Web config (SSH)"})
        result["remote_hostname"] = result.pop("hostname", "")
        self.store.update(host.alias, **result, domains=list(domains.values()), inspected=now())
        self.store.audit(host.alias, "SSH inspection", f"{len(result['users'])} users; {len(domains)} domains")

    def record_authorised_key(self, host, public):
        import hashlib,base64
        fingerprint='SHA256:'+base64.b64encode(hashlib.sha256(base64.b64decode(public.split()[1])).digest()).decode().rstrip('=')
        users=self.store.get(host.alias).get('users',[])
        user=next((u for u in users if u['user']==host.user),None)
        if user is None:
            user=dict(user=host.user,uid=None,shell='',home='',keys=[]);users.append(user)
        if not any(k.get('fingerprint')==fingerprint for k in user.get('keys',[])):
            user.setdefault('keys',[]).append(dict(fingerprint=fingerprint,public_key=public))
        self.store.update(host.alias,users=users)

    async def authorise_ssh_key(self, host):
        from .key_import import matching_public_key
        from .secure import Setup, SecureTransport, provision
        if self.vault.path.exists() and not self.vault.cipher and not await self.action_unlock.__wrapped__(self):return
        initial=''
        while True:
            selected=await self.push_screen_wait(Form('Authorise SSH Key',[
                ('identity','SSH Key',initial,False)],f'Authorise a key for {host.user}@{host.alias}.',
                'Continue',key_pickers={'identity'},key_list_only=True))
            if selected is None:return
            initial=selected['identity'];selected.clear()
            choice=await self.push_screen_wait(Form('Disable password SSH logins?',[
                ('key_only','Disable password SSH logins?','no',False)],
                f'Applies to {host.user}@{host.alias}. Key-only access is enabled only after a fresh login using the chosen key succeeds.',
                'Authorise',choices={'key_only':['no','yes']}))
            if choice is None:continue
            key_only=choice['key_only']=='yes';choice.clear()
            break
        keypath=str(Path(initial).expanduser().resolve())
        self.busy=self.key_setup_running=True
        self.setup_title="Authorise SSH Key"
        self.setup_completed=[];self.setup_stage=0
        self.setup_stages=6 if key_only else 4
        self.setup_countdown=None;self.setup_error=''
        def done(message):
            self.setup_completed.append(message);self.dirty=True
        def progress(message):
            if message.startswith('Reconnecting'):done('Key-only SSH policy applied')
            self.setup_stage=min(self.setup_stages,self.setup_stage+1)
            self.say(message)
        def recovery(error,seconds):
            self.setup_error=error;self.setup_countdown=seconds;self.dirty=True
        def audit(action,outcome):
            self.store.audit(host.alias,action,outcome)
            if action=='Account prepared':
                done('Connected as '+host.user);done('SSH key authorised')
                self.record_authorised_key(host,public)
            elif action=='New login verified':done('Fresh key login and sudo access verified')
            elif action=='SSH policy rolled back':done('SSH policy rolled back')
        async def save():
            values=dict(alias=host.alias,hostname=host.hostname,user=host.user,port=str(host.port),identity=keypath)
            if host.host_key_alias:values['hostkeyalias']=host.host_key_alias
            await asyncio.to_thread(self.config.save,values,host)
            done('Connection updated to use the selected key')
        try:
            public=self.read_public_key(keypath+'.pub')
            password=self.sudo_password(host)
            plan=Setup(host.user,keypath,public,password,bootstrap_password=password,reuse_existing=True,passwordless=True,lock_root=False,block_bootstrap=False,key_only=key_only)
            transport=SecureTransport(self.config,host,plan)
            if key_only:
                await provision(transport,save,audit,progress,recovery)
                done('Key-only SSH access confirmed; recovery timer cancelled')
            else:
                progress('Connecting as '+host.user+' and authorising SSH key…')
                await asyncio.to_thread(transport.authorise_key)
                audit('Account prepared','SSH key authorised; existing account settings preserved')
                progress('Verifying a fresh connection using the selected key…')
                await asyncio.to_thread(self.remote.verify_key,host,keypath)
                done('Fresh key login verified')
                progress('Updating local connection…');await save()
                done('SSH password-login settings retained')
                self.store.audit(host.alias,'SSH key authorised',host.user+' · password-login policy unchanged')
            self.setup_stage=self.setup_stages
            await self.push_screen_wait(ProgressComplete('SSH key authorised'))
        except Exception as error:
            self.store.audit(host.alias,'SSH key authorisation stopped',str(error))
            completed='\n'.join('✓ '+action for action in self.setup_completed)
            await self.push_screen_wait(Viewer('SSH key authorisation stopped',str(error)+'\n\n'+completed,compact=True))
        finally:
            self.busy=self.key_setup_running=False
            self.setup_error='';self.setup_countdown=None
            await self.refresh_inventory(force=True)

    @background("interaction")
    async def action_operations(self):
        if self.demo or self.busy:
            return
        host = await self.choose_action_host()
        if not host:
            return
        if self.vault.path.exists() and not self.vault.cipher and not await self.action_unlock.__wrapped__(self):return
        while True:
            current_hosts=await asyncio.to_thread(self.config.discover)
            fresh=next((entry for entry in current_hosts if entry.alias==host.alias),None)
            if fresh is None:
                await self.push_screen_wait(Viewer('Connection unavailable','This SSH connection was removed. Select another connection.',compact=True))
                return
            host=fresh
            panel=KeyAdmin(f'{host.user}@{host.alias}')
            async def load():
                try:
                    from .key_import import matching_public_key
                    server=await asyncio.to_thread(self.remote.run,host,'inspect-keys',user=host.user)
                    def pairs():
                        return {key['fingerprint']:str(Path(key['path']).with_suffix('')) for key in self.scan_keys() if matching_public_key(Path(key['path']).with_suffix(''))}
                    private=await asyncio.to_thread(pairs)
                    unique={}
                    for key in server['keys']:
                        public=key['public_key']
                        label=key.get('line',public).split(public,1)[-1].strip() or public.split()[0]
                        unique.setdefault(key['fingerprint'],dict(key,label=label,local_private=private.get(key['fingerprint'],'')))
                    panel.keys=list(unique.values())
                    users=self.store.get(host.alias).get('users',[])
                    account=next((u for u in users if u['user']==host.user),None)
                    if account is None:
                        account=dict(user=host.user,uid=None,shell='',home='',keys=[]);users.append(account)
                    account['keys']=server['keys'];self.store.update(host.alias,users=users)
                except Exception as error:panel.error=str(error)
                finally:panel.loading=False;self.dirty=True
            task=asyncio.create_task(load())
            try:choice=await self.push_screen_wait(panel)
            finally:
                if not task.done():task.cancel()
                await asyncio.gather(task,return_exceptions=True)
            if choice is None:return
            op,key=choice
            if op=='refresh':continue
            if op=='add':
                await self.authorise_ssh_key(host);continue
            missing=not key.get('local_private')
            warning='No matching private key is available on this computer. This key may belong to another person or device; changing it can remove their access.'
            if op=='cycle':
                if missing and await self.push_screen_wait(Form('Private key not available',[],warning,'Continue',overview=True,default_cancel=True,text_colour=2)) is None:continue
                await self.rotate_key_wizard(host,current_key=key)
            elif op=='revoke':
                text=f"Revoke key for {host.user}@{host.alias}?\n{key['fingerprint']}\nFuture connections using this key will stop working. Existing sessions remain open."
                if missing:text+='\n'+warning
                if len(panel.keys)==1:text+='\nThis is the only authorised key for this account.'
                if await self.push_screen_wait(Form('Revoke SSH Key',[],text,'Revoke',overview=True,default_cancel=True,highlights={warning:2} if missing else {})) is None:continue
                self.busy=True
                try:
                    await asyncio.to_thread(self.remote.run,host,'revoke-key',user=host.user,key=key['public_key'])
                    users=self.store.get(host.alias).get('users',[])
                    for account in users:
                        if account['user']==host.user:account['keys']=[k for k in account.get('keys',[]) if k['fingerprint']!=key['fingerprint']]
                    self.store.update(host.alias,users=users)
                    self.store.audit(host.alias,'SSH key revoked',key['fingerprint'])
                    self.render_table()
                except Exception as error:
                    await self.push_screen_wait(Viewer('Key revocation stopped',str(error),compact=True))
                finally:self.busy=False

    async def rotate_key_wizard(self, host, current_key=None):
        from .config import digest
        if host.proxy or host.patterns!=[host.alias]:
            await self.push_screen_wait(Viewer('Cannot rotate key','Rotation requires a direct connection with its own SSH config entry.',compact=True));return
        if self.vault.path.exists() and not self.vault.cipher and not await self.action_unlock.__wrapped__(self):return
        if current_key is not None:
            current=current_key
        else:
            self.busy=self.key_setup_running=True
            self.setup_title='Check Current SSH Key';self.setup_completed=[]
            self.setup_stage=1;self.setup_stages=1;self.setup_error='';self.setup_countdown=None
            self.say('Reading authorised SSH keys from '+host.alias+'…')
            try:
                from .key_import import matching_public_key
                server=await asyncio.to_thread(self.remote.run,host,'inspect-keys',user=host.user)
                authorised={key['fingerprint']:key for key in server['keys']}
                def local_matches():
                    return [key for key in self.scan_keys() if key['fingerprint'] in authorised and matching_public_key(Path(key['path']).with_suffix(''))]
                local=await asyncio.to_thread(local_matches)
                # Prefer the configured/default file when identical key copies exist.
                preferred=await asyncio.to_thread(self.default_key,host.alias,host.hostname,host.user)
                local.sort(key=lambda key:str(Path(key['path']).with_suffix(''))!=preferred)
                unique={}
                for key in local:unique.setdefault(key['fingerprint'],key)
                local=list(unique.values())
                if not local:raise ValueError('No server-authorised key matches a local private/public key pair. Import the current key pair before rotating it.')
            except Exception as error:
                await self.push_screen_wait(Viewer('Cannot check current SSH key',str(error),compact=True))
                return
            finally:
                self.busy=self.key_setup_running=False
            if len(local)>1:
                paths=[str(Path(key['path']).with_suffix('')) for key in local]
                choice=await self.push_screen_wait(Form('Choose server-authorised key',[
                    ('identity','Key to replace',paths[0],False)],'Multiple local keys are authorised for this account. Choose which one to rotate.',
                    'Continue',choices={'identity':paths}))
                if choice is None:return
                current=next(key for key in local if str(Path(key['path']).with_suffix(''))==choice['identity']);choice.clear()
            else:current=local[0]
        oldpath=Path(current['local_private']) if current.get('local_private') else Path(current['path']).with_suffix('') if current.get('path') else None
        old_name=str(oldpath) if oldpath else current.get('label',current['fingerprint'])
        selected=await self.push_screen_wait(Form('Rotate Key · current key',[
            ('identity','Current SSH Key',old_name,False),
            ('fingerprint','Server-confirmed fingerprint',current['fingerprint'],False)],
            f'Checked on {host.user}@{host.alias}. This key is currently authorised on the server.',
            'Continue',read_only={'identity','fingerprint'}))
        if selected is None:return
        selected.clear()
        new=await self.new_key_dialog(defer=True)
        if new is None:return
        try:
            newpath=Path(new['path']).expanduser().resolve()
            oldkey=current_key['public_key'] if current_key is not None else self.read_public_key(str(oldpath)+'.pub')
            if oldpath is not None and newpath==oldpath.resolve():raise ValueError('Choose a different replacement key filename.')
            review=f'Account: {host.user}@{host.alias}\nNew key: {newpath.name}\nOld key to revoke: {oldpath.name if oldpath else old_name}\nThe new key is installed and verified before the old public key is removed from the server. Local old-key files are retained.'
            if await self.push_screen_wait(Form('Rotate Key · review',[],review,'Rotate',overview=True,default_cancel=True,highlights={review.split('\n')[-1]:6})) is None:return
            self.busy=self.key_setup_running=True
            self.setup_title='Rotate SSH Key';self.setup_completed=[]
            self.setup_stage=0;self.setup_stages=5;self.setup_error='';self.setup_countdown=None
            def done(message):
                self.setup_completed.append(message);self.setup_stage=min(5,len(self.setup_completed));self.say(message)
            self.say('Creating replacement key pair…')
            await asyncio.to_thread(create_key,str(newpath),new['label'],new['passphrase'])
            self.store.audit('local','Key created',str(newpath))
            self.key_rows=await asyncio.to_thread(self.scan_keys)
            self.render_table()
            public=self.read_public_key(str(newpath)+'.pub')
            done('Replacement key pair created')
            if new['passphrase']:
                from .secure import askpass
                def load_agent():
                    with askpass(new['passphrase'],str(newpath),kind='key') as env:
                        result=subprocess.run(['ssh-add',str(newpath)],env=env,capture_output=True,text=True,start_new_session=os.name!='nt',timeout=20)
                    if result.returncode:raise ValueError('The replacement key was created but could not be unlocked in ssh-agent. Start your SSH agent, load the key, then retry.')
                await asyncio.to_thread(load_agent)
            current=await asyncio.to_thread(self.config.discover)
            related=[h for h in current if h.signature==host.signature]
            if any(h.proxy or h.patterns!=[h.alias] for h in related):raise ValueError('Related aliases need their own direct SSH config entries before rotation.')
            self.rotation_revisions={str(h.source):digest(h.source) for h in related}
            payload=dict(user=host.user,newpath=str(newpath),newkey=public,oldkey=oldkey,related_aliases=[h.alias for h in related])
            await self.rotate(host,payload,done)
            self.setup_stage=self.setup_stages
            await self.push_screen_wait(ProgressComplete('SSH key rotated'))
        except Exception as error:
            self.store.audit(host.alias,'Key rotation stopped',str(error))
            await self.push_screen_wait(Viewer('Key rotation stopped',str(error)+'\nCheck Activity for completed stages. Local old-key files are retained.',compact=True))
        finally:
            new.clear();self.busy=self.key_setup_running=False;self.setup_title='';self.setup_error='';self.setup_countdown=None
            await self.refresh_inventory(force=True)

    @staticmethod
    def read_public_key(path):
        path = Path(path).expanduser()
        if path.suffix != ".pub":
            raise ValueError("Choose a .pub file; private keys must never be sent to a server.")
        value = path.read_text().strip()
        if "\n" in value or not value.startswith(("ssh-", "ecdsa-", "sk-")):
            raise ValueError("Expected a single OpenSSH public key.")
        result = subprocess.run(["ssh-keygen", "-lf", str(path)], capture_output=True, text=True, timeout=5)
        if result.returncode:
            raise ValueError("Invalid OpenSSH public key.")
        return value

    async def rotate(self, host, payload, completed=None):
        user = payload["user"]
        done=completed or (lambda message:None)
        # Preflight config revision and isolated login semantics before any change.
        from .config import digest
        expected = getattr(self, "rotation_revisions", {}).get(str(host.source), host.revision)
        if digest(host.source) != expected:
            raise ValueError("SSH config changed. Refresh before rotating.")
        await asyncio.to_thread(self.remote.run, host, "add-key", user=user, key=payload["newkey"])
        self.record_authorised_key(host,payload["newkey"])
        done("Replacement public key authorised on the server")
        self.store.audit(host.alias, "Rotation phase", "New key authorised; old key retained")
        await asyncio.to_thread(self.remote.verify_key, host, payload["newpath"])
        done("Fresh login with replacement key verified")
        self.store.audit(host.alias, "Rotation phase", "Independent login using new key verified")
        # Re-discover to account for earlier edits in a bulk rotation sharing a file.
        current = await asyncio.to_thread(self.config.discover)
        fresh = next(h for h in current if h.alias == host.alias)
        if fresh.signature != host.signature:
            raise ValueError("Connection changed during rotation; old key retained.")
        aliases = [h.alias for h in current if h.signature == fresh.signature and h.alias in payload.get("related_aliases", [host.alias])]
        for alias in aliases:
            # Earlier aliases may have changed offsets in the same source file.
            latest = await asyncio.to_thread(self.config.discover)
            entry = next(h for h in latest if h.alias == alias)
            expected = getattr(self, "rotation_revisions", {}).get(str(entry.source), entry.revision)
            if digest(entry.source) != expected:
                raise ValueError("SSH config changed during rotation; old key retained.")
            await asyncio.to_thread(self.config.save, {"alias": entry.alias, "hostname": entry.hostname, "port": str(entry.port), "user": entry.user, "identity": payload["newpath"]}, entry)
            if hasattr(self, "rotation_revisions"):
                self.rotation_revisions[str(entry.source)] = digest(entry.source)
        done("Local SSH connections updated to the replacement key")
        await asyncio.to_thread(self.remote.run, fresh, "revoke-key", user=user, key=payload["oldkey"])
        import hashlib,base64
        old_fingerprint='SHA256:'+base64.b64encode(hashlib.sha256(base64.b64decode(payload['oldkey'].split()[1])).digest()).decode().rstrip('=')
        for alias in payload.get('related_aliases',[host.alias]):
            users=self.store.get(alias).get('users',[])
            for account in users:
                if account['user']==user:
                    account['keys']=[key for key in account.get('keys',[]) if key.get('fingerprint')!=old_fingerprint]
            self.store.update(alias,users=users)
        done("Old public key revoked and removed from the server")
        self.store.audit(host.alias,"Key rotation complete","Old public key removed after replacement login verification")
        try:await self.inspect_host(fresh)
        except Exception:self.store.audit(host.alias,"Rotation inspection pending","Rotation completed; refresh inspection separately")
        self.refresh_inventory(force=True)
        return "New key verified, SSH config updated, old key revoked"

    async def action_quit(self):
        if self.busy:
            self.say("An operation is running. Wait for its result before quitting.")
            return
        self.vault.lock()
        self.exit()
