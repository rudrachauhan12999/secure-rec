"""Task 12 - Kerberos authentication (concise educational simulation).

NOT a Kerberos implementation: no ASN.1, no network protocol, single process.
It models the three Kerberos exchanges and the checks that make them secure.

Problem Kerberos solves: a user should prove their identity to many network
services without sending their password to each one (or across the network
at all).  A trusted Key Distribution Center (KDC) shares a long-term secret
key with every principal and issues time-limited *tickets*.

    Client --(1) AS-REQ------------------> Authentication Server (KDC)
           <-(2) AS-REP: TGT + {K_c,tgs}K_client
    Client --(3) TGS-REQ: TGT + Authenticator --> Ticket Granting Server (KDC)
           <-(4) TGS-REP: Service Ticket + {K_c,s}K_c,tgs
    Client --(5) AP-REQ: Service Ticket + Authenticator --> Application Server
           <-(6) AP-REP: {timestamp}K_c,s   (mutual authentication)

* TGT (Ticket-Granting Ticket) = {client, K_c,tgs, validity}K_tgs - encrypted
  for the TGS; the client carries it but cannot read or forge it.  It proves
  "the AS authenticated this client recently" so the password is needed once.
* Service Ticket = {client, K_c,s, validity}K_service - proves to the
  application server that the KDC vouches for the client.
* Authenticator = {client, timestamp}session key - proves the presenter
  knows the session key inside the ticket (a stolen ticket alone is useless)
  and, with timestamps + a replay cache, stops replays.

Crypto: AES-128-GCM (authenticated) for every sealed structure; client key =
PBKDF2-HMAC-SHA256(password, salt=realm+principal).  The KDC stores only the
derived key.  The demo password is generated at runtime and never output.
A simulated clock makes the run reproducible for demonstration; keys and
nonces still come from the OS CSPRNG.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core import crypto_utils as cu
from core.file_handler import task_output_dir
from core.key_manager import generate_aes_key, key_fingerprint
from core.results import Status, TaskResult, guarded
from tasks.common import cli_main

TASK_ID = "task12"
TITLE = "Task 12 - Kerberos Authentication (simulation)"

REALM = "SECURE-REC.LOCAL"
CLIENT = f"student01@{REALM}"
TGS = f"krbtgt/{REALM}@{REALM}"
SERVICE = f"fileserver/records.secure-rec.local@{REALM}"
TICKET_LIFETIME = timedelta(hours=8)
MAX_SKEW = timedelta(minutes=5)
PBKDF2_ITERATIONS = 100_000
DEFAULT_START = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)


class KerberosError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code


class SimClock:
    def __init__(self, start: datetime):
        self.now = start

    def advance(self, delta: timedelta) -> None:
        self.now += delta


# ------------------------------------------------------------------- helpers
def string_to_key(password: str, principal: str) -> bytes:
    """Password -> AES-128 long-term key (salted, slow KDF; like Kerberos string-to-key)."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), f"{REALM}{principal}".encode(),
                               PBKDF2_ITERATIONS, dklen=16)


def seal(obj: dict, key: bytes, label: str) -> bytes:
    """Encrypt+authenticate a structure; ``label`` (AAD) binds it to its purpose."""
    return cu.aes_gcm_encrypt(json.dumps(obj, sort_keys=True).encode(), key, aad=label.encode())


def unseal(blob: bytes, key: bytes, label: str, error_code: str) -> dict:
    try:
        return json.loads(cu.aes_gcm_decrypt(blob, key, aad=label.encode()))
    except ValueError:
        raise KerberosError(error_code, f"cannot decrypt/authenticate {label.split('|')[0]}") from None


def b64(key: bytes) -> str:
    return base64.b64encode(key).decode()


def unb64(text: str) -> bytes:
    return base64.b64decode(text)


def ts(dt: datetime) -> str:
    return dt.isoformat()


def check_fresh(ctime: str, clock: SimClock) -> None:
    if abs(clock.now - datetime.fromisoformat(ctime)) > MAX_SKEW:
        raise KerberosError("KRB_AP_ERR_SKEW", "timestamp outside allowed clock skew (5 min)")


def check_valid(ticket: dict, clock: SimClock) -> None:
    if clock.now > datetime.fromisoformat(ticket["endtime"]):
        raise KerberosError("KRB_AP_ERR_TKT_EXPIRED", f"ticket expired at {ticket['endtime']}")


class ReplayCache:
    def __init__(self):
        self._seen: set[tuple] = set()

    def check_and_add(self, auth: dict) -> None:
        key = (auth["client"], auth["ctime"], auth["cnonce"])
        if key in self._seen:
            raise KerberosError("KRB_AP_ERR_REPEAT", "authenticator already used (replay)")
        self._seen.add(key)


# ----------------------------------------------------------------------- KDC
class KDC:
    """Authentication Server + Ticket Granting Server sharing one principal database."""

    def __init__(self, clock: SimClock):
        self.clock = clock
        self._db: dict[str, bytes] = {TGS: generate_aes_key(128)}  # principal -> long-term key
        self._replay = ReplayCache()

    def register_user(self, principal: str, password: str) -> None:
        self._db[principal] = string_to_key(password, principal)   # password itself is not stored

    def register_service(self, principal: str) -> bytes:
        """Returns the service's long-term key (a 'keytab' installed on that server)."""
        self._db[principal] = generate_aes_key(128)
        return self._db[principal]

    def _issue(self, client: str, server: str, authtime: str) -> tuple[bytes, bytes, str]:
        session_key = generate_aes_key(128)
        endtime = ts(self.clock.now + TICKET_LIFETIME)
        ticket = seal({"client": client, "server": server, "session_key": b64(session_key),
                       "authtime": authtime, "endtime": endtime}, self._db[server], f"ticket|{server}")
        return ticket, session_key, endtime

    # Authentication Server
    def as_exchange(self, req: dict) -> dict:
        client = req["client"]
        if client not in self._db:
            raise KerberosError("KDC_ERR_C_PRINCIPAL_UNKNOWN", client)
        # Pre-authentication: only someone knowing the password-derived key can seal this timestamp.
        pa = unseal(req["padata"], self._db[client], "pa-enc-timestamp", "KDC_ERR_PREAUTH_FAILED")
        check_fresh(pa["timestamp"], self.clock)
        tgt, k_c_tgs, endtime = self._issue(client, TGS, ts(self.clock.now))
        enc_part = seal({"session_key": b64(k_c_tgs), "nonce": req["nonce"], "endtime": endtime,
                         "server": TGS}, self._db[client], "as-rep")
        return {"client": client, "ticket": tgt, "enc_part": enc_part}

    # Ticket Granting Server
    def tgs_exchange(self, req: dict) -> dict:
        tgt = unseal(req["ticket"], self._db[TGS], f"ticket|{TGS}", "KRB_AP_ERR_BAD_INTEGRITY")
        check_valid(tgt, self.clock)
        k_c_tgs = unb64(tgt["session_key"])
        auth = unseal(req["authenticator"], k_c_tgs, "authenticator", "KRB_AP_ERR_BAD_INTEGRITY")
        if auth["client"] != tgt["client"]:
            raise KerberosError("KRB_AP_ERR_BADMATCH", "authenticator client does not match ticket")
        check_fresh(auth["ctime"], self.clock)
        self._replay.check_and_add(auth)
        if req["service"] not in self._db:
            raise KerberosError("KDC_ERR_S_PRINCIPAL_UNKNOWN", req["service"])
        ticket, k_c_s, endtime = self._issue(tgt["client"], req["service"], tgt["authtime"])
        enc_part = seal({"session_key": b64(k_c_s), "nonce": req["nonce"], "endtime": endtime,
                         "server": req["service"]}, k_c_tgs, "tgs-rep")
        return {"ticket": ticket, "enc_part": enc_part}


# ---------------------------------------------------------- application server
class AppServer:
    def __init__(self, principal: str, service_key: bytes, clock: SimClock):
        self.principal, self._key, self.clock = principal, service_key, clock
        self._replay = ReplayCache()

    def ap_exchange(self, req: dict) -> tuple[str, bytes]:
        """Returns (authenticated client name, AP-REP)."""
        ticket = unseal(req["ticket"], self._key, f"ticket|{self.principal}", "KRB_AP_ERR_BAD_INTEGRITY")
        check_valid(ticket, self.clock)
        k_c_s = unb64(ticket["session_key"])
        auth = unseal(req["authenticator"], k_c_s, "authenticator", "KRB_AP_ERR_BAD_INTEGRITY")
        if auth["client"] != ticket["client"]:
            raise KerberosError("KRB_AP_ERR_BADMATCH", "authenticator client does not match ticket")
        check_fresh(auth["ctime"], self.clock)
        self._replay.check_and_add(auth)
        return ticket["client"], seal({"ctime": auth["ctime"]}, k_c_s, "ap-rep")


# ------------------------------------------------------------------- client
class Client:
    def __init__(self, principal: str, password: str, clock: SimClock):
        self.principal, self.clock = principal, clock
        self._key = string_to_key(password, principal)    # the password is not kept
        self.tgt: bytes | None = None
        self.k_c_tgs: bytes | None = None
        self.service_ticket: bytes | None = None
        self.k_c_s: bytes | None = None

    def authenticator(self, key: bytes) -> bytes:
        return seal({"client": self.principal, "ctime": ts(self.clock.now), "cnonce": secrets.randbits(32)},
                    key, "authenticator")

    def as_request(self) -> dict:
        self._nonce = secrets.randbits(32)
        return {"client": self.principal, "service": TGS, "nonce": self._nonce,
                "padata": seal({"timestamp": ts(self.clock.now)}, self._key, "pa-enc-timestamp")}

    def process_as_reply(self, rep: dict) -> None:
        enc = unseal(rep["enc_part"], self._key, "as-rep", "CLIENT_DECRYPT_FAILED")
        if enc["nonce"] != self._nonce:
            raise KerberosError("CLIENT_NONCE_MISMATCH", "AS reply does not answer our request")
        self.tgt, self.k_c_tgs = rep["ticket"], unb64(enc["session_key"])

    def tgs_request(self, service: str) -> dict:
        self._nonce = secrets.randbits(32)
        return {"ticket": self.tgt, "authenticator": self.authenticator(self.k_c_tgs),
                "service": service, "nonce": self._nonce}

    def process_tgs_reply(self, rep: dict) -> None:
        enc = unseal(rep["enc_part"], self.k_c_tgs, "tgs-rep", "CLIENT_DECRYPT_FAILED")
        if enc["nonce"] != self._nonce:
            raise KerberosError("CLIENT_NONCE_MISMATCH", "TGS reply does not answer our request")
        self.service_ticket, self.k_c_s = rep["ticket"], unb64(enc["session_key"])

    def ap_request(self) -> dict:
        return {"ticket": self.service_ticket, "authenticator": self.authenticator(self.k_c_s)}

    def verify_ap_reply(self, rep: bytes, sent_req: dict) -> bool:
        """Mutual authentication: only the real server could decrypt the ticket and answer."""
        mine = unseal(sent_req["authenticator"], self.k_c_s, "authenticator", "CLIENT_DECRYPT_FAILED")
        return unseal(rep, self.k_c_s, "ap-rep", "KRB_AP_ERR_MUT_FAIL")["ctime"] == mine["ctime"]


# ------------------------------------------------------------------ scenario
def attempt(fn) -> str:
    """Run a step expected to be rejected; return the rejection code (or 'ACCEPTED')."""
    try:
        fn()
        return "ACCEPTED"
    except KerberosError as exc:
        return str(exc)


@guarded(TASK_ID, TITLE)
def run(input_path: str | Path | None = None, output_root: Path | None = None,
        password: str | None = None, start_time: datetime = DEFAULT_START) -> TaskResult:
    """``input_path`` is accepted for a uniform interface but not needed."""
    out_dir = task_output_dir(TASK_ID, output_root)
    clock = SimClock(start_time)
    password = password or secrets.token_urlsafe(16)      # runtime-only demo credential
    log: list[str] = []

    def step(text: str) -> None:
        log.append(f"[{clock.now:%H:%M:%S}] {text}")

    # Setup: registration (out of band, before any login).
    kdc = KDC(clock)
    kdc.register_user(CLIENT, password)
    fileserver = AppServer(SERVICE, kdc.register_service(SERVICE), clock)
    client = Client(CLIENT, password, clock)
    step(f"Setup: realm {REALM}; KDC stores long-term keys for {CLIENT} (from password via PBKDF2), "
         f"{TGS} and {SERVICE}")

    # (1)-(2) AS exchange.
    as_req = client.as_request()
    step(f"(1) Client -> AS   AS-REQ: client={CLIENT}, service={TGS}, nonce, "
         f"pre-auth timestamp encrypted with client key ({len(as_req['padata'])} B). Password NOT sent.")
    as_rep = kdc.as_exchange(as_req)
    step("    AS: decrypted pre-auth timestamp with stored client key -> client knows the password; "
         "timestamp fresh")
    step(f"(2) AS -> Client   AS-REP: TGT ({len(as_rep['ticket'])} B, sealed with TGS key - opaque to client) "
         f"+ enc-part sealed with client key")
    client.process_as_reply(as_rep)
    step(f"    Client: decrypted enc-part with its password key -> TGS session key fp "
         f"{key_fingerprint(client.k_c_tgs)}")

    # (3)-(4) TGS exchange.
    tgs_req = client.tgs_request(SERVICE)
    step(f"(3) Client -> TGS  TGS-REQ: TGT + Authenticator{{client, time}}K_c,tgs, service={SERVICE}")
    tgs_rep = kdc.tgs_exchange(tgs_req)
    step("    TGS: opened TGT with its own key, got K_c,tgs, verified authenticator (name match, fresh, not replayed)")
    step(f"(4) TGS -> Client  TGS-REP: Service Ticket ({len(tgs_rep['ticket'])} B, sealed with service key) "
         f"+ enc-part sealed with K_c,tgs")
    client.process_tgs_reply(tgs_rep)
    step(f"    Client: service session key fp {key_fingerprint(client.k_c_s)}")

    # (5)-(6) AP exchange.
    ap_req = client.ap_request()
    step("(5) Client -> App  AP-REQ: Service Ticket + Authenticator{client, time}K_c,s")
    authenticated_as, ap_rep = fileserver.ap_exchange(ap_req)
    step(f"    AppServer: ticket decrypted with its service key; authenticator valid -> CLIENT AUTHENTICATED "
         f"as {authenticated_as}")
    mutual = client.verify_ap_reply(ap_rep, ap_req)
    step(f"(6) App -> Client  AP-REP: {{timestamp}}K_c,s -> client verified server: {mutual} "
         f"(mutual authentication)")
    happy = authenticated_as == CLIENT and mutual

    # Negative scenarios.
    step("--- Attack / failure scenarios ---")
    impostor = Client(CLIENT, password + "-wrong", clock)
    neg = {"wrong_password": attempt(lambda: kdc.as_exchange(impostor.as_request()))}
    step(f"N1 Wrong password at AS                  -> {neg['wrong_password']}")

    forged = bytearray(client.tgt)
    forged[20] ^= 0x01
    client_copy = {"ticket": bytes(forged), "authenticator": client.authenticator(client.k_c_tgs),
                   "service": SERVICE, "nonce": 1}
    neg["forged_tgt"] = attempt(lambda: kdc.tgs_exchange(client_copy))
    step(f"N2 Modified TGT presented to TGS         -> {neg['forged_tgt']}")

    thief_req = {"ticket": client.service_ticket,
                 "authenticator": seal({"client": CLIENT, "ctime": ts(clock.now), "cnonce": 7},
                                       generate_aes_key(128), "authenticator")}
    neg["stolen_ticket"] = attempt(lambda: fileserver.ap_exchange(thief_req))
    step(f"N3 Stolen ticket, no session key         -> {neg['stolen_ticket']}")

    neg["replay"] = attempt(lambda: fileserver.ap_exchange(ap_req))
    step(f"N4 Replay of captured AP-REQ             -> {neg['replay']}")

    clock.advance(TICKET_LIFETIME + timedelta(minutes=1))
    neg["expired_ticket"] = attempt(lambda: fileserver.ap_exchange(client.ap_request()))
    step(f"N5 Same ticket after 8 h 1 min           -> {neg['expired_ticket']}")

    expected_codes = {"wrong_password": "KDC_ERR_PREAUTH_FAILED", "forged_tgt": "KRB_AP_ERR_BAD_INTEGRITY",
                      "stolen_ticket": "KRB_AP_ERR_BAD_INTEGRITY", "replay": "KRB_AP_ERR_REPEAT",
                      "expired_ticket": "KRB_AP_ERR_TKT_EXPIRED"}
    rejected = {k: neg[k].startswith(code) for k, code in expected_codes.items()}

    transcript = out_dir / "transcript.txt"
    transcript.write_text(
        "Kerberos simulation (educational, single process, simulated clock)\n"
        "Secrets (password, long-term keys, session keys) are never printed; keys appear as fingerprints.\n\n"
        + __doc__.split("Problem Kerberos solves:")[1].split("Crypto:")[0].strip() + "\n\n"
        + "\n".join(log) + "\n", encoding="utf-8")

    passed = happy and all(rejected.values())
    result = TaskResult(TASK_ID, TITLE, status=Status.PASS if passed else Status.FAIL, artifacts=[transcript])
    if not passed:
        result.reason = "Kerberos flow or rejection checks failed."
    result.add("Entities", f"Client {CLIENT} | AS + TGS (KDC) | Application Server {SERVICE}")
    result.add("(1-2) AS exchange", "PASS - pre-authenticated, TGT issued" if client.tgt else "FAIL")
    result.add("(3-4) TGS exchange", "PASS - service ticket issued" if client.service_ticket else "FAIL")
    result.add("(5) AP exchange", f"PASS - server authenticated client as {authenticated_as}")
    result.add("(6) Mutual authentication", "PASS - client verified server" if mutual else "FAIL")
    result.add("TGT", f"{len(client.tgt)} bytes AES-GCM under TGS key, valid {TICKET_LIFETIME}")
    result.add("Service ticket", f"{len(client.service_ticket)} bytes AES-GCM under service key")
    labels = {"wrong_password": "N1 wrong password", "forged_tgt": "N2 modified TGT",
              "stolen_ticket": "N3 stolen ticket w/o session key", "replay": "N4 replayed request",
              "expired_ticket": "N5 expired ticket"}
    for k, label in labels.items():
        result.add(label, f"{'REJECTED' if rejected[k] else 'NOT REJECTED'} ({neg[k]})")
    result.add("Password handling", "never sent over the network, never stored by KDC, never written to output")
    result.data = {"authenticated_client": authenticated_as, "mutual_authentication": mutual,
                   "rejections": neg, "rejected": rejected, "tgt_bytes": len(client.tgt),
                   "service_ticket_bytes": len(client.service_ticket)}
    result.details = (
        "What is authenticated:\n"
        "  AS:  the client proves knowledge of its password-derived key (encrypted timestamp).\n"
        "  TGS: the TGT shows the AS authenticated the client; the authenticator proves the\n"
        "       presenter holds the TGT session key.\n"
        "  App: the service ticket shows the KDC vouches for the client; the authenticator\n"
        "       proves possession of the service session key. AP-REP authenticates the server\n"
        "       back to the client.\n"
        "Why tickets exist: the password is used once per login (single sign-on). Services\n"
        "never see it and never need to contact the KDC. Tickets expire and authenticators\n"
        "are timestamped, which limits theft and replay.\n"
        "Simplifications: no ASN.1/network protocol, one realm, no renewal, forwarding,\n"
        "cross-realm or PAC. AES-GCM stands in for Kerberos' AES-CTS-HMAC enctypes."
    )
    result.save(out_dir)
    return result


if __name__ == "__main__":
    cli_main(run, __doc__.splitlines()[0], takes_file=False)
