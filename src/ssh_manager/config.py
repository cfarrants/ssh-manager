"""Discover aliases without rewriting OpenSSH's configuration language.
OpenSSH itself resolves effective settings; editing is deliberately limited to
unambiguous single-alias Host blocks. Includes retain their original paths.
"""
from __future__ import annotations
import dataclasses
import glob
import hashlib
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import time


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else "missing"


def atomic_write(path: Path, content: bytes, mode: int = 0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".ssh-manager-", dir=path.parent)
    try:
        os.fchmod(fd, mode) if hasattr(os, "fchmod") else None
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


@dataclasses.dataclass
class Host:
    alias: str
    source: Path
    start: int
    end: int
    patterns: list[str]
    revision: str
    hostname: str = ""
    user: str = ""
    port: int = 22
    identities: list[str] = dataclasses.field(default_factory=list)
    proxy: str = ""
    error: str = ""
    host_key_alias: str = ""

    @property
    def signature(self):
        return f"{self.hostname.lower()}|{self.port}|{self.user}"


class SSHConfig:
    def __init__(self, path: Path):
        self.path = path.expanduser().resolve()
        self.revisions = {}
        self.warnings = []

    def changed(self):
        return not self.revisions or any(digest(Path(p)) != d for p, d in self.revisions.items())

    def discover(self, resolve=True):
        self.revisions = {}
        self.warnings = []
        found: dict[str, Host] = {}
        seen = set()

        def visit(path, conditional=False):
            path = Path(path).resolve()
            if path in seen:
                return
            seen.add(path)
            self.revisions[str(path)] = digest(path)
            if not path.exists():
                return
            lines = path.read_text().splitlines(keepends=True)
            boundaries = []
            for i, line in enumerate(lines):
                try:
                    parts = shlex.split(line, comments=True)
                except ValueError:
                    self.warnings.append(f"Could not parse {path.name}:{i+1}")
                    continue
                if not parts:
                    continue
                # OpenSSH permits 'Keyword=value'.
                if "=" in parts[0]:
                    key, value = parts.pop(0).split("=", 1)
                    parts = [key, value, *parts]
                key = parts[0].lower()
                if key in ("host", "match"):
                    boundaries.append((i, key, parts[1:]))
                if key == "include":
                    for pattern in parts[1:]:
                        pattern = os.path.expanduser(pattern)
                        if not os.path.isabs(pattern):
                            pattern = str(self.path.parent / pattern)
                        for child in sorted(glob.glob(pattern)):
                            scoped = bool(boundaries) and boundaries[-1][1:] != ("host", ["*"])
                            visit(child, conditional=conditional or scoped)
            for n, (start, key, patterns) in enumerate(boundaries):
                if key != "host":
                    continue
                end = boundaries[n+1][0] if n+1 < len(boundaries) else len(lines)
                for alias in patterns:
                    if any(c in alias for c in "*?![]") or alias.startswith("-"):
                        continue
                    if alias in found:
                        found[alias].patterns.append("<duplicate>")
                        continue
                    host = Host(alias, path, start, end, patterns.copy(), digest(path))
                    if conditional:
                        host.patterns.append("<conditional include>")
                    found[alias] = host
        visit(self.path)
        # Watch the root directory's includes additions as well as file content.
        self._inventory = self._include_inventory()
        if resolve:
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(self.resolve, found.values()))
        return sorted(found.values(), key=lambda h: h.alias.lower())

    def _include_inventory(self):
        inventory = []
        for source in self.revisions:
            p = Path(source)
            if not p.exists():
                continue
            for line in p.read_text().splitlines():
                try:
                    bits = shlex.split(line, comments=True)
                except ValueError:
                    continue
                if bits and bits[0].lower() == "include":
                    for pattern in bits[1:]:
                        pattern = os.path.expanduser(pattern)
                        if not os.path.isabs(pattern):
                            pattern = str(self.path.parent / pattern)
                        inventory.extend(sorted(glob.glob(pattern)))
        return inventory

    def needs_refresh(self):
        return self.changed() or self._include_inventory() != getattr(self, "_inventory", [])

    def resolve(self, host):
        try:
            result = subprocess.run(["ssh", "-G", "-F", str(self.path), "--", host.alias], capture_output=True, text=True, timeout=8)
            if result.returncode:
                raise ValueError(result.stderr.strip())
            values = {}
            for line in result.stdout.splitlines():
                key, _, value = line.partition(" ")
                values.setdefault(key, []).append(value)
            host.hostname = values.get("hostname", [host.alias])[0]
            host.user = values.get("user", [""])[0]
            host.port = int(values.get("port", ["22"])[0])
            host.identities = values.get("identityfile", [])
            host.host_key_alias = values.get("hostkeyalias", [""])[0]
            host.proxy = values.get("proxyjump", values.get("proxycommand", [""]))[0]
            if host.proxy == "none":
                host.proxy = ""
        except Exception as error:
            host.hostname = host.alias
            host.error = str(error)
        return host

    def explicit_identities(self, host):
        values = []
        for line in host.source.read_text().splitlines()[host.start+1:host.end]:
            match = re.match(r"\s*IdentityFile(?:\s+|=)(.*)", line, re.IGNORECASE)
            if match:
                bits = shlex.split(match.group(1), comments=True)
                if bits:
                    values.append(bits[0])
        return values

    def _commit(self, path, lines, revision):
        if digest(path) != revision:
            raise ValueError("SSH config changed outside the app. Refresh and retry; nothing was overwritten.")
        if path.exists():
            self.backup(path)
        atomic_write(path, "".join(lines).encode())

    def backup(self, path):
        # Keep backups out of Include globs such as conf.d/*.
        directory = path.parent / ".ssh-manager-backups"
        directory.mkdir(exist_ok=True, mode=0o700)
        backup = directory / f"{path.name}-{time.time_ns()}.bak"
        shutil.copy2(path, backup)
        backup.chmod(0o600)
        return backup

    def save(self, values: dict, host: Host | None = None):
        alias = values["alias"].strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", alias):
            raise ValueError("Alias must use letters, numbers, dots, hyphens or underscores.")
        hostname = values["hostname"].strip()
        if not re.fullmatch(r"[A-Za-z0-9_.:%\[\]-]+", hostname) or hostname.startswith("-"):
            raise ValueError("Enter a hostname or IP address without spaces.")
        port = int(values.get("port") or 22)
        if not 1 <= port <= 65535:
            raise ValueError("Port must be 1–65535.")
        user = values.get("user", "").strip()
        if user and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*\$?", user):
            raise ValueError("Invalid SSH username.")
        identity = values.get("identity", "").strip()
        if any(c in identity for c in '\n\r"'):
            raise ValueError("Invalid identity path.")
        existing = self.discover(resolve=False)
        if any(h.alias == alias and (host is None or h.alias != host.alias) for h in existing):
            raise ValueError("That SSH alias already exists.")
        if host and host.patterns != [host.alias]:
            raise ValueError("This alias shares a Host block, is duplicated, or is conditional. Use the config editor (Shift+X) to preserve its rules.")
        path = host.source if host else self.path
        revision = host.revision if host else digest(path)
        lines = path.read_text().splitlines(keepends=True) if path.exists() else []
        fields = {"hostname": hostname, "user": user, "port": str(port), "identityfile": identity}
        if values.get("hostkeyalias"):
            alias_value = values["hostkeyalias"]
            if not re.fullmatch(r"[A-Za-z0-9_.:%\[\]-]+", alias_value):
                raise ValueError("Invalid host key alias.")
            fields["hostkeyalias"] = alias_value
        if host:
            block = lines[host.start:host.end]
            new = [f"Host {alias}\n"]
            for line in block[1:]:
                match = re.match(r"\s*(\w+)(?:\s+|=)", line)
                key = match.group(1).lower() if match else ""
                if key in fields:
                    continue
                new.append(line)
            # Explicit options must precede preserved options in this block.
            new[1:1] = [f'    {key} "{value}"\n' for key, value in fields.items() if value]
            lines[host.start:host.end] = new
        else:
            # Prepend so existing Host * defaults do not shadow new values.
            # Restore global scope before the original preamble/Includes.
            lines = [f"Host {alias}\n", *[f'    {key} "{value}"\n' for key, value in fields.items() if value], "\nHost *\n", *lines]
        self._commit(path, lines, revision)
        return alias

    def remove(self, host):
        if host.patterns != [host.alias]:
            raise ValueError("Shared/conditional/duplicate Host block: use the config editor (Shift+X).")
        lines = host.source.read_text().splitlines(keepends=True)
        del lines[host.start:host.end]
        self._commit(host.source, lines, host.revision)
