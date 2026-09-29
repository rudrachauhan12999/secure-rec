"""Task 12: Kerberos simulation."""

from __future__ import annotations

from datetime import timedelta

import pytest

from core.results import Status
from tasks import task12_kerberos as t12


def test_full_flow_and_all_attacks_rejected(out_root):
    result = t12.run(output_root=out_root)
    assert result.status is Status.PASS, result.reason
    assert result.data["authenticated_client"] == t12.CLIENT
    assert result.data["mutual_authentication"] is True
    assert all(result.data["rejected"].values())


def test_password_and_keys_never_written(out_root, monkeypatch):
    password = "Viva-Demo-Password-123"
    keys = []
    real = t12.generate_aes_key
    monkeypatch.setattr(t12, "generate_aes_key", lambda bits=128: keys.append(real(bits)) or keys[-1])
    t12.run(output_root=out_root, password=password)
    client_key = t12.string_to_key(password, t12.CLIENT)
    content = b"".join(f.read_bytes() for f in (out_root / "task12").iterdir())
    assert password.encode() not in content
    for k in [client_key, *keys]:
        assert k not in content and k.hex().encode() not in content
        assert t12.b64(k).encode() not in content


def test_transcript_is_reproducible_for_a_viva(out_root, tmp_path):
    t12.run(output_root=out_root)
    first = (out_root / "task12" / "transcript.txt").read_text().splitlines()
    t12.run(output_root=tmp_path / "second")
    second = (tmp_path / "second" / "task12" / "transcript.txt").read_text().splitlines()
    strip = lambda lines: [ln.split(" fp ")[0] for ln in lines]  # noqa: E731 - fingerprints are random
    assert strip(first) == strip(second)
    assert first[-1].startswith("[17:01:00]") and any(ln.startswith("[09:00:00] (1)") for ln in first)


# ---------------------------------------------------------------- unit level
@pytest.fixture
def realm():
    clock = t12.SimClock(t12.DEFAULT_START)
    kdc = t12.KDC(clock)
    kdc.register_user(t12.CLIENT, "pw")
    server = t12.AppServer(t12.SERVICE, kdc.register_service(t12.SERVICE), clock)
    client = t12.Client(t12.CLIENT, "pw", clock)
    client.process_as_reply(kdc.as_exchange(client.as_request()))
    client.process_tgs_reply(kdc.tgs_exchange(client.tgs_request(t12.SERVICE)))
    return clock, kdc, server, client


def _code(fn):
    with pytest.raises(t12.KerberosError) as exc:
        fn()
    return exc.value.code


def test_ticket_is_opaque_to_client(realm):
    _, _, _, client = realm
    with pytest.raises(t12.KerberosError):
        t12.unseal(client.tgt, client.k_c_tgs, f"ticket|{t12.TGS}", "X")


def test_kdc_rejects_unknown_principals(realm):
    clock, kdc, _, client = realm
    stranger = t12.Client(f"nobody@{t12.REALM}", "pw", clock)
    assert _code(lambda: kdc.as_exchange(stranger.as_request())) == "KDC_ERR_C_PRINCIPAL_UNKNOWN"
    assert _code(lambda: kdc.tgs_exchange(client.tgs_request("ghost@X"))) == "KDC_ERR_S_PRINCIPAL_UNKNOWN"


def test_clock_skew_rejected(realm):
    clock, kdc, _, client = realm
    old_request = client.as_request()
    clock.advance(timedelta(minutes=10))
    assert _code(lambda: kdc.as_exchange(old_request)) == "KRB_AP_ERR_SKEW"


def test_authenticator_for_other_client_rejected(realm):
    clock, _, server, client = realm
    other = t12.Client(f"other@{t12.REALM}", "x", clock)
    req = {"ticket": client.service_ticket, "authenticator": other.authenticator(client.k_c_s)}
    assert _code(lambda: server.ap_exchange(req)) == "KRB_AP_ERR_BADMATCH"


def test_ticket_for_other_service_rejected(realm):
    clock, kdc, _, client = realm
    other_server = t12.AppServer(f"mail/x@{t12.REALM}", kdc.register_service(f"mail/x@{t12.REALM}"), clock)
    assert _code(lambda: other_server.ap_exchange(client.ap_request())) == "KRB_AP_ERR_BAD_INTEGRITY"


def test_wrong_password_client_cannot_read_as_reply(realm):
    clock, kdc, _, _ = realm
    good = t12.Client(t12.CLIENT, "pw", clock)
    reply = kdc.as_exchange(good.as_request())
    bad = t12.Client(t12.CLIENT, "not-pw", clock)
    bad._nonce = good._nonce
    assert _code(lambda: bad.process_as_reply(reply)) == "CLIENT_DECRYPT_FAILED"
