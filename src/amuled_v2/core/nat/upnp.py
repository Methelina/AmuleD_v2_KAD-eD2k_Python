"""UPnP IGD / NAT-PMP port mapping for the serve listener (stage X).

Pure asyncio, no external dependencies.  Two independent transports are
tried in order:

1. UPnP IGD: SSDP M-SEARCH for ``InternetGatewayDevice`` -> device
   description XML -> first ``WANIPConnection``/``WANPPPConnection``
   control URL -> SOAP ``AddPortMapping``.
2. NAT-PMP: UDP request to the default gateway on port 5351.

A mapping attempt never raises into the caller: failures are reported in
the returned result dict (lowid stays a cosmetic problem, not a crash).
The mapping is public-external-port == local bind port (eMule behaviour).

src/amuled_v2/core/nat/upnp.py
Version:     0.1.0
Author:      Soror L.'.L.'.
Updated:     2026-09-26

Patch Notes v0.1.0 (Soror L'.L'.):
  [+] Added SSDP discovery + SOAP AddPortMapping and NAT-PMP TCP mapping.
"""

from __future__ import annotations

import asyncio
import re
import socket
import struct
from typing import Any
from urllib.parse import urlsplit
from urllib.request import urlopen

from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.NAT, "core.nat.upnp")

SSDP_ADDR = ("239.255.255.250", 1900)
SSDP_ST = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
NAT_PMP_PORT = 5351
_MAP_LIFETIME_S = 7200
_TIMEOUT = 4.0


def _default_gateway() -> str | None:
    """Best-effort default gateway on Windows and Linux, no deps."""
    try:
        import subprocess
        import sys

        if sys.platform == "win32":
            out = subprocess.run(
                ["route", "print", "0.0.0.0"], capture_output=True, text=True,
                timeout=5,
            ).stdout
            m = re.search(
                r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)",
                out, re.MULTILINE,
            )
            return m.group(1) if m else None
        with open("/proc/net/route", encoding="ascii") as fh:
            for line in fh.readlines()[1:]:
                parts = line.split()
                if len(parts) > 3 and parts[1] == "00000000":
                    raw = bytes.fromhex(parts[2])
                    return socket.inet_ntoa(raw[::-1])
    except Exception:
        return None
    return None


def _local_ip_for(gateway: str) -> str | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((gateway, NAT_PMP_PORT))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


async def _ssdp_discover() -> str | None:
    """Return the first device-description Location URL from SSDP."""
    loop = asyncio.get_running_loop()

    def _search() -> str | None:
        msg = (
            "M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {SSDP_ADDR[0]}:{SSDP_ADDR[1]}\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 2\r\n"
            f"ST: {SSDP_ST}\r\n\r\n"
        ).encode("ascii")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.settimeout(_TIMEOUT)
        try:
            s.sendto(msg, SSDP_ADDR)
            while True:
                data, _addr = s.recvfrom(4096)
                m = re.search(rb"(?i)location:\s*(\S+)", data)
                if m:
                    return m.group(1).decode("ascii")
        except (OSError, TimeoutError):
            return None
        finally:
            s.close()

    return await asyncio.wait_for(
        loop.run_in_executor(None, _search), timeout=_TIMEOUT + 2.0
    )


def _soap_request(control_url: str, service_type: str, action: str,
                  body_args: str) -> str:
    """Blocking SOAP POST; returns the raw response body text."""
    import urllib.request as rq

    soap = (
        '<?xml version="1.0"?>'
        f'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        f's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        f"<s:Body><u:{action} xmlns:u=\"{service_type}\">{body_args}"
        f"</u:{action}></s:Body></s:Envelope>"
    )
    req = rq.Request(
        control_url,
        data=soap.encode("utf-8"),
        headers={
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPACTION": f'"{service_type}#{action}"',
        },
        method="POST",
    )
    with rq.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310 (LAN router)
        return resp.read().decode("utf-8", errors="replace")


async def _upnp_map(local_ip: str, port: int) -> dict[str, Any]:
    """UPnP IGD AddPortMapping for the serve TCP port."""
    loop = asyncio.get_running_loop()
    location = await _ssdp_discover()
    if not location:
        return {"via": "upnp", "ok": False, "reason": "no IGD in SSDP answer"}

    def _fetch_control() -> tuple[str, str]:
        xml = urlopen(location, timeout=_TIMEOUT).read().decode(  # noqa: S310
            "utf-8", errors="replace"
        )
        stype = ""
        control = ""
        for svc in re.finditer(
            r"<service>(.*?)</service>", xml, re.DOTALL | re.IGNORECASE
        ):
            body = svc.group(1)
            st = re.search(
                r"(?i)<serviceType>\s*"
                r"(?:urn:schemas-upnp-org:service:)"
                r"(WAN(?:IP|PPP)Connection):\d*\s*</serviceType>",
                body,
            )
            cu = re.search(
                r"(?i)<controlURL>\s*(.*?)\s*</controlURL>", body
            )
            if st and cu and not control:
                stype = f"urn:schemas-upnp-org:service:{st.group(1)}:1"
                control = cu.group(1)
        if not control:
            raise RuntimeError("WANIPConnection service not found in device XML")
        if not control.startswith(("http://", "https://")):
            split = urlsplit(location)
            control = f"{split.scheme}://{split.netloc}{control}"
        return control, stype

    try:
        control, stype = await loop.run_in_executor(None, _fetch_control)
        args = (
            f"<NewRemoteHost></NewRemoteHost>"
            f"<NewExternalPort>{port}</NewExternalPort>"
            f"<NewProtocol>TCP</NewProtocol>"
            f"<NewInternalPort>{port}</NewInternalPort>"
            f"<NewInternalClient>{local_ip}</NewInternalClient>"
            f"<NewEnabled>1</NewEnabled>"
            f"<NewPortMappingDescription>AmuleD serve</NewPortMappingDescription>"
            f"<NewLeaseDuration>{_MAP_LIFETIME_S}</NewLeaseDuration>"
        )
        await loop.run_in_executor(
            None, lambda: _soap_request(control, stype, "AddPortMapping", args)
        )
        return {"via": "upnp", "ok": True, "external_port": port}
    except Exception as exc:
        return {"via": "upnp", "ok": False, "reason": repr(exc)}


async def _natpmp_map(gateway: str, port: int) -> dict[str, Any]:
    """NAT-PMP TCP mapping against the default gateway."""
    loop = asyncio.get_running_loop()

    def _request() -> dict[str, Any]:
        # version 0, op 2 (map TCP), reserved, internal port, external port,
        # lifetime — all u16/u32 big endian per RFC 6886.
        req = struct.pack(
            ">BBHHHI", 0, 2, 0, port, port, _MAP_LIFETIME_S
        )
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(_TIMEOUT)
        try:
            s.sendto(req, (gateway, NAT_PMP_PORT))
            data, _addr = s.recvfrom(32)
            if len(data) >= 16:
                # RFC 6886 reply: ver(1) op(1) result(2) epoch(4)
                # private(2) public(2) lifetime(4) = 16 bytes
                _ver, _op, result, _epoch, _private, public, _life = (
                    struct.unpack(">BBHIHHI", data[:16])
                )
                if result == 0:
                    return {"via": "nat-pmp", "ok": True,
                            "external_port": public}
                return {"via": "nat-pmp", "ok": False,
                        "reason": f"result={result}"}
            return {"via": "nat-pmp", "ok": False, "reason": "short reply"}
        except (OSError, TimeoutError) as exc:
            return {"via": "nat-pmp", "ok": False, "reason": repr(exc)}
        finally:
            s.close()

    return await asyncio.wait_for(
        loop.run_in_executor(None, _request), timeout=_TIMEOUT
    )


async def map_tcp_port(port: int, *, natpmp: bool = True) -> dict[str, Any]:
    """Try UPnP, then NAT-PMP.  Never raises; returns a result dict."""
    gateway = await asyncio.get_running_loop().run_in_executor(
        None, _default_gateway
    )
    local_ip = _local_ip_for(gateway) if gateway else None
    if gateway is None or local_ip is None:
        return {"ok": False, "reason": "default gateway or local ip unknown"}

    try:
        upnp = await _upnp_map(local_ip, port)
    except Exception as exc:  # never let a router probe crash the kernel
        log.debug("NAT upnp probe failed: error=%r", exc)
        upnp = {"via": "upnp", "ok": False, "reason": repr(exc)}
    if upnp.get("ok"):
        log.info("NAT upnp mapping ok: port=%d, ip=%s", port, local_ip)
        return upnp

    if natpmp:
        try:
            pmp = await _natpmp_map(gateway, port)
            if pmp.get("ok"):
                log.info("NAT-PMP mapping ok: port=%d, gw=%s", port, gateway)
                return pmp
        except Exception as exc:  # timeout on the await itself
            return {"ok": False, "reason": repr(exc), "upnp": upnp}
        return {"ok": False, "upnp": upnp, "natpmp": pmp}
    return {"ok": False, "upnp": upnp}


async def unmap_tcp_port(port: int) -> dict[str, Any]:
    """Best-effort UPnP DeletePortMapping (NAT-PMP mappings expire alone)."""
    loop = asyncio.get_running_loop()
    location = await _ssdp_discover()
    if not location:
        return {"ok": False, "reason": "no IGD"}

    def _delete() -> None:
        control, stype = "", ""
        xml = urlopen(location, timeout=_TIMEOUT).read().decode(  # noqa: S310
            "utf-8", errors="replace"
        )
        for svc in re.finditer(
            r"<service>(.*?)</service>", xml, re.DOTALL | re.IGNORECASE
        ):
            body = svc.group(1)
            st = re.search(
                r"(?i)<serviceType>\s*(?:urn:schemas-upnp-org:service:)"
                r"(WAN(?:IP|PPP)Connection):\d*\s*</serviceType>", body,
            )
            cu = re.search(
                r"(?i)<controlURL>\s*(.*?)\s*</controlURL>", body
            )
            if st and cu and not control:
                stype = f"urn:schemas-upnp-org:service:{st.group(1)}:1"
                control = cu.group(1)
        if control and not control.startswith(("http://", "https://")):
            split = urlsplit(location)
            control = f"{split.scheme}://{split.netloc}{control}"
        if control:
            args = (
                "<NewRemoteHost></NewRemoteHost>"
                f"<NewExternalPort>{port}</NewExternalPort>"
                "<NewProtocol>TCP</NewProtocol>"
            )
            _soap_request(control, stype, "DeletePortMapping", args)

    try:
        await loop.run_in_executor(None, _delete)
        return {"ok": True}
    except Exception as exc:
        return {"ok": False, "reason": repr(exc)}
