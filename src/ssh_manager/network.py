from __future__ import annotations
import ipaddress
import socket
import time
import dns.resolver
from .store import now


def addresses(hostname):
    return sorted({item[4][0] for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)})


def public(address):
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        return False


def check(host):
    stamp = now()
    if host.error:
        return dict(status="CONFIG ERROR", checked=stamp, error=host.error)
    if host.proxy:
        # Opening a proxy transport on every tick may execute arbitrary local
        # ProxyCommand programs or generate repeated authentication attempts.
        return dict(status="VIA PROXY", checked=stamp, error="Use SSH inspection to verify this route; direct probes are skipped.")
    start = time.monotonic()
    ips = None
    try:
        ips = addresses(host.hostname)
        with socket.create_connection((host.hostname, host.port), timeout=3):
            pass
        return dict(status="ONLINE", checked=stamp, latency=round((time.monotonic()-start)*1000), addresses=ips, public_ips=[ip for ip in ips if public(ip)], error="")
    except (OSError, ValueError) as error:
        result = dict(status="OFFLINE", checked=stamp, error=str(error))
        if ips is not None:
            result.update(addresses=ips, public_ips=[ip for ip in ips if public(ip)])
        return result


def ping(host):
    """A lightweight TCP ping to the configured SSH port; no authentication."""
    if host.error:return dict(status='CONFIG ERROR')
    if host.proxy:return dict(status='VIA PROXY')
    start=time.monotonic()
    try:
        with socket.create_connection((host.hostname,host.port),timeout=1.5):pass
        return dict(status='ONLINE',latency=round((time.monotonic()-start)*1000))
    except (OSError,ValueError):
        return dict(status='OFFLINE')


def reverse(ips):
    rows = []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3
    for ip in ips:
        try:
            name = str(resolver.resolve_address(ip)[0]).rstrip(".")
            rows.append({"name": name, "source": "PTR"})
        except dns.exception.DNSException:
            continue
    return rows


def valid_domain(value):
    value = value.strip().rstrip(".").lower().encode("idna").decode()
    import re
    if len(value) > 253 or "." not in value or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in value.split(".")):
        raise ValueError("Enter a domain name, for example example.com, without a URL path or wildcard.")
    return value


def verify_domains(domains, ips):
    rows = []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3
    for item in domains:
        row = dict(item)
        resolved = set()
        errors = []
        for kind in ("A", "AAAA"):
            try:
                resolved.update(str(r) for r in resolver.resolve(row["name"], kind))
            except dns.resolver.NoAnswer:
                pass
            except dns.exception.DNSException as e:
                errors.append(type(e).__name__)
        row.update(addresses=sorted(resolved), checked=now(), status="POINTS HERE" if resolved.intersection(ips) else ("ELSEWHERE" if resolved and ips else "NO TARGET IP" if resolved else "NO DNS"), error=", ".join(errors))
        rows.append(row)
    return rows
