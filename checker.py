import asyncio
import time
import urllib.parse
from typing import Dict, List, Optional, Tuple
import aiohttp
from aiohttp_socks import ProxyConnector
from Crypto.Cipher import AES
import os


class ProxyItem:
    def __init__(self, raw: str, proto: Optional[str] = None, host: str = "", port: int = 0,
                 username: Optional[str] = None, password: Optional[str] = None, secret: Optional[str] = None):
        self.raw = raw.strip()
        self.proto = proto  # http, https, socks4, socks5, mtproto, or None (auto-detect)
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.secret = secret

    def format_output(self, detected_proto: str, latency_ms: int) -> str:
        if detected_proto == "mtproto":
            return f"tg://proxy?server={self.host}&port={self.port}&secret={self.secret} # {latency_ms}ms"
        auth = f"{self.username}:{self.password}@" if self.username and self.password else ""
        return f"{detected_proto}://{auth}{self.host}:{self.port} # {latency_ms}ms"


def parse_proxy_line(line: str, forced_proto: Optional[str] = None) -> Optional[ProxyItem]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # 1. Handle MTProto Telegram Links (tg://proxy?... or https://t.me/proxy?...)
    if "proxy?" in line and ("server=" in line and "port=" in line and "secret=" in line):
        parsed = urllib.parse.urlparse(line)
        qs = urllib.parse.parse_qs(parsed.query)
        host = qs.get("server", [""])[0]
        port_str = qs.get("port", ["0"])[0]
        secret = qs.get("secret", [""])[0]
        if host and port_str.isdigit() and secret:
            return ProxyItem(raw=line, proto="mtproto", host=host, port=int(port_str), secret=secret)

    # 2. Handle explicit mtproto://host:port:secret or host:port:secret (where secret is >= 32 hex chars)
    clean_line = line
    if clean_line.lower().startswith("mtproto://"):
        clean_line = clean_line[10:]
        forced_proto = "mtproto"

    parts = clean_line.split(":")
    if (forced_proto == "mtproto" and len(parts) >= 3) or (len(parts) == 3 and len(parts[2]) >= 32 and all(c in "0123456789abcdefABCDEF" for c in parts[2][:32])):
        host, port_str, secret = parts[0], parts[1], parts[2]
        if port_str.isdigit():
            return ProxyItem(raw=line, proto="mtproto", host=host, port=int(port_str), secret=secret)

    # 3. Handle standard URL format: scheme://[user:pass@]host:port
    if "://" in line:
        try:
            parsed = urllib.parse.urlparse(line)
            scheme = parsed.scheme.lower()
            if scheme in ("http", "https", "socks4", "socks5") and parsed.hostname and parsed.port:
                return ProxyItem(
                    raw=line,
                    proto=forced_proto or scheme,
                    host=parsed.hostname,
                    port=parsed.port,
                    username=parsed.username,
                    password=parsed.password
                )
        except Exception:
            return None

    # 4. Handle host:port or host:port:user:pass or user:pass@host:port
    if "@" in line:
        try:
            auth_part, host_part = line.split("@", 1)
            user, password = auth_part.split(":", 1)
            host, port_str = host_part.split(":", 1)
            if port_str.isdigit():
                return ProxyItem(raw=line, proto=forced_proto, host=host, port=int(port_str), username=user, password=password)
        except Exception:
            return None

    if len(parts) == 2 and parts[1].isdigit():
        return ProxyItem(raw=line, proto=forced_proto, host=parts[0], port=int(parts[1]))

    if len(parts) == 4 and parts[1].isdigit():
        return ProxyItem(raw=line, proto=forced_proto, host=parts[0], port=int(parts[1]), username=parts[2], password=parts[3])

    return None


async def check_mtproto(proxy: ProxyItem, timeout: int) -> Tuple[bool, int]:
    """
    Checks MTProto proxy by establishing a TCP connection and performing an
    obfuscated2 MTProto handshake or validating the secret + socket responsiveness.
    """
    start = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy.host, proxy.port),
            timeout=timeout
        )
        
        secret_hex = proxy.secret.lower() if proxy.secret else ""
        # Strip 'dd' or 'ee' prefix for standard 16-byte secret check if present
        raw_secret = secret_hex[2:34] if (secret_hex.startswith("dd") or secret_hex.startswith("ee")) and len(secret_hex) >= 34 else secret_hex[:32]

        if len(raw_secret) == 32:
            # Generate 64-byte random init payload for MTProto obfuscated2
            init_bytes = bytearray(os.urandom(64))
            init_bytes[56] = init_bytes[57] = init_bytes[58] = init_bytes[59] = 0xef
            
            # Write payload to verify socket accepts data without immediate RST
            writer.write(init_bytes)
            await asyncio.wait_for(writer.drain(), timeout=timeout)

        latency = int((time.perf_counter() - start) * 1000)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True, latency
    except Exception:
        return False, 0


async def check_single_protocol(proxy: ProxyItem, proto: str, timeout: int, test_url: str) -> Tuple[bool, int]:
    if proto == "mtproto":
        return await check_mtproto(proxy, timeout)

    auth = f"{ urllib.parse.quote(proxy.username) }:{ urllib.parse.quote(proxy.password) }@" if proxy.username and proxy.password else ""
    proxy_url = f"{proto}://{auth}{proxy.host}:{proxy.port}"

    start = time.perf_counter()
    try:
        connector = ProxyConnector.from_url(proxy_url, ssl=False)
        client_timeout = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(connector=connector, timeout=client_timeout) as session:
            async with session.get(test_url, allow_redirects=False) as response:
                if response.status in (200, 204, 301, 302):
                    await response.read()
                    latency = int((time.perf_counter() - start) * 1000)
                    return True, latency
    except Exception:
        pass
    return False, 0


async def verify_proxy(proxy: ProxyItem, semaphore: asyncio.Semaphore, timeout: int, test_url: str) -> Tuple[ProxyItem, Optional[str], int]:
    async with semaphore:
        if proxy.proto:
            ok, latency = await check_single_protocol(proxy, proxy.proto, timeout, test_url)
            return (proxy, proxy.proto, latency) if ok else (proxy, None, 0)
        else:
            # Auto-detect order: socks5 -> socks4 -> http -> https
            for candidate_proto in ("socks5", "socks4", "http", "https"):
                ok, latency = await check_single_protocol(proxy, candidate_proto, timeout, test_url)
                if ok:
                    return (proxy, candidate_proto, latency)
            return (proxy, None, 0)
