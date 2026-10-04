"""
secproto_client.py - Minimal Python implementation of the secure TCP protocol
client side for black-box / gray-box testing.

Implements:
  - Frame encoding/decoding (37-byte header + payload)
  - Handshake (X25519 + Ed25519 + HKDF + AES-256-GCM)
  - AEAD encrypt/decrypt with AAD
  - Per-direction seq counters

This is a TEST implementation. It is NOT production-hardened and is intended
only to exercise the Go server's protocol handling.
"""
import os
import socket
import struct
import time
import hashlib
import hmac

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Protocol constants (must match the Go server)
# ---------------------------------------------------------------------------
MAGIC = 0x5343
PROTOCOL_VERSION = 1
HEADER_SIZE = 37  # 2+1+1+1+8+12+8+4

# Message types
MSG_CLIENT_HELLO = 1
MSG_SERVER_HELLO = 2
MSG_SERVER_PROOF = 3
MSG_CLIENT_FINISHED = 4
MSG_SERVER_FINISHED = 5
MSG_DATA = 6
MSG_HEARTBEAT = 7
MSG_REKEY = 8
MSG_ALERT = 9

# Cipher suites
CIPHER_AES256GCM = 1

# Time windows (nanoseconds)
TIMESTAMP_WINDOW_NS = 60 * 10**9

# HKDF labels (must match Go)
INFO_HANDSHAKE = b"secproto/v1/handshake"
INFO_TRAFFIC = b"secproto/v1/traffic"
LABEL_CLIENT_KEY = b"client write key"
LABEL_SERVER_KEY = b"server write key"
LABEL_CLIENT_NONCE = b"client nonce"
LABEL_SERVER_NONCE = b"server nonce"
LABEL_SESSION_ID = b"session id"


# ---------------------------------------------------------------------------
# Minimal protobuf encoder/decoder for handshake messages
# ---------------------------------------------------------------------------
def _encode_varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def _decode_varint(data, pos):
    result = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


def _field_key(field_num, wire_type):
    return _encode_varint((field_num << 3) | wire_type)


def _encode_bytes_field(field_num, value):
    return _field_key(field_num, 2) + _encode_varint(len(value)) + value


def _encode_varint_field(field_num, value):
    return _field_key(field_num, 0) + _encode_varint(value)


def _encode_packed_varints(field_num, values):
    packed = b"".join(_encode_varint(v) for v in values)
    return _field_key(field_num, 2) + _encode_varint(len(packed)) + packed


def _parse_fields(data):
    """Return list of (field_num, wire_type, value_bytes)."""
    fields = []
    pos = 0
    while pos < len(data):
        key, pos = _decode_varint(data, pos)
        field_num = key >> 3
        wire_type = key & 0x7
        if wire_type == 0:  # varint
            val, pos = _decode_varint(data, pos)
            fields.append((field_num, wire_type, val))
        elif wire_type == 2:  # length-delimited
            length, pos = _decode_varint(data, pos)
            val = data[pos:pos + length]
            pos += length
            fields.append((field_num, wire_type, val))
        elif wire_type == 5:  # 32-bit
            val = data[pos:pos + 4]
            pos += 4
            fields.append((field_num, wire_type, val))
        else:
            raise ValueError(f"unsupported wire type {wire_type}")
    return fields


class ClientHello:
    def __init__(self, version, cipher_suites, client_random,
                 client_eph_pubkey, client_identity_pubkey):
        self.version = version
        self.cipher_suites = cipher_suites
        self.client_random = client_random
        self.client_eph_pubkey = client_eph_pubkey
        self.client_identity_pubkey = client_identity_pubkey

    def marshal(self):
        return (
            _encode_varint_field(1, self.version)
            + _encode_packed_varints(2, self.cipher_suites)
            + _encode_bytes_field(3, self.client_random)
            + _encode_bytes_field(4, self.client_eph_pubkey)
            + _encode_bytes_field(5, self.client_identity_pubkey)
        )


class ServerHello:
    def __init__(self, version=0, cipher_suite=0, server_random=b"",
                 server_eph_pubkey=b"", server_identity_pubkey=b""):
        self.version = version
        self.cipher_suite = cipher_suite
        self.server_random = server_random
        self.server_eph_pubkey = server_eph_pubkey
        self.server_identity_pubkey = server_identity_pubkey

    @classmethod
    def unmarshal(cls, data):
        obj = cls()
        for fn, wt, val in _parse_fields(data):
            if fn == 1 and wt == 0:
                obj.version = val
            elif fn == 2 and wt == 0:
                obj.cipher_suite = val
            elif fn == 3 and wt == 2:
                obj.server_random = val
            elif fn == 4 and wt == 2:
                obj.server_eph_pubkey = val
            elif fn == 5 and wt == 2:
                obj.server_identity_pubkey = val
        return obj


class ServerProof:
    def __init__(self, signature=b""):
        self.signature = signature

    @classmethod
    def unmarshal(cls, data):
        obj = cls()
        for fn, wt, val in _parse_fields(data):
            if fn == 1 and wt == 2:
                obj.signature = val
        return obj


class ClientFinished:
    def __init__(self, signature):
        self.signature = signature

    def marshal(self):
        return _encode_bytes_field(1, self.signature)


class ServerFinished:
    def __init__(self, success=False):
        self.success = success

    @classmethod
    def unmarshal(cls, data):
        obj = cls()
        for fn, wt, val in _parse_fields(data):
            if fn == 1 and wt == 0:
                obj.success = bool(val)
        return obj


class Rekey:
    def __init__(self, new_key_id=0, new_random=b""):
        self.new_key_id = new_key_id
        self.new_random = new_random

    def marshal(self):
        return (
            _encode_varint_field(1, self.new_key_id)
            + _encode_bytes_field(3, self.new_random)
        )


# ---------------------------------------------------------------------------
# Frame encoding/decoding
# ---------------------------------------------------------------------------
def build_frame(msg_type, key_id, seq, payload, timestamp_ns=None):
    if timestamp_ns is None:
        timestamp_ns = time.time_ns()
    nonce = b"\x00" * 12  # server recomputes nonce from seq+prefix
    header = struct.pack(">HBBBQ", MAGIC, PROTOCOL_VERSION, msg_type,
                         key_id, seq)
    header += nonce
    header += struct.pack(">Q", timestamp_ns)
    header += struct.pack(">I", len(payload))
    return header + payload


def parse_frame(data):
    if len(data) < HEADER_SIZE:
        raise ValueError("frame too short")
    magic, version, msg_type, key_id, seq = struct.unpack(">HBBBQ", data[:13])
    nonce = data[13:25]
    timestamp = struct.unpack(">Q", data[25:33])[0]
    length = struct.unpack(">I", data[33:37])[0]
    payload = data[37:37 + length]
    return {
        "magic": magic, "version": version, "msg_type": msg_type,
        "key_id": key_id, "seq": seq, "nonce": nonce,
        "timestamp": timestamp, "length": length, "payload": payload,
    }


def header_bytes_for_aad(frame_dict):
    """Reconstruct the AAD header bytes: Magic||Ver||Type||KeyID||Seq||Ts."""
    return struct.pack(">HBBBQ", frame_dict["magic"], frame_dict["version"],
                       frame_dict["msg_type"], frame_dict["key_id"],
                       frame_dict["seq"]) + struct.pack(">Q", frame_dict["timestamp"])


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------
def hkdf_expand(prk, label, length):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=label)
    return hkdf.derive(prk)


def derive_session_keys(shared, client_random, server_random):
    salt = client_random + server_random
    # handshake_secret
    hs = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
              info=INFO_HANDSHAKE).derive(shared)
    # traffic_secret
    ts = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
              info=INFO_TRAFFIC).derive(hs)
    return {
        "client_key": hkdf_expand(ts, LABEL_CLIENT_KEY, 32),
        "server_key": hkdf_expand(ts, LABEL_SERVER_KEY, 32),
        "client_nonce_prefix": hkdf_expand(ts, LABEL_CLIENT_NONCE, 4),
        "server_nonce_prefix": hkdf_expand(ts, LABEL_SERVER_NONCE, 4),
        "session_id": hkdf_expand(ts, LABEL_SESSION_ID, 8),
        "traffic_secret": ts,
    }


def nonce_for_seq(prefix, seq):
    return prefix + struct.pack(">Q", seq)


def derive_rekey_keys(prev_traffic_secret, new_random):
    """Derive new session keys for a rekey, matching Go's DeriveRekeyKeys.

    ikm = prev_traffic_secret || new_random
    traffic_secret = HKDF(ikm, "", "secproto/v1/traffic")
    Then expand sub-keys with the same labels as derive_session_keys.
    """
    ikm = prev_traffic_secret + new_random
    ts = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
              info=INFO_TRAFFIC).derive(ikm)
    return {
        "client_key": hkdf_expand(ts, LABEL_CLIENT_KEY, 32),
        "server_key": hkdf_expand(ts, LABEL_SERVER_KEY, 32),
        "client_nonce_prefix": hkdf_expand(ts, LABEL_CLIENT_NONCE, 4),
        "server_nonce_prefix": hkdf_expand(ts, LABEL_SERVER_NONCE, 4),
        "session_id": hkdf_expand(ts, LABEL_SESSION_ID, 8),
        "traffic_secret": ts,
    }


# ---------------------------------------------------------------------------
# SecureClient - implements the client side of the protocol
# ---------------------------------------------------------------------------
class SecureClient:
    def __init__(self, host, port, identity_privkey=None, identity_pubkey=None,
                 peer_pubkey=None):
        self.host = host
        self.port = port
        self.sock = None
        self.identity_privkey = identity_privkey or Ed25519PrivateKey.generate()
        self.identity_pubkey = (identity_pubkey
                                or self.identity_privkey.public_key())
        self.peer_pubkey = peer_pubkey  # optional pinning

        # Session state (set after handshake)
        self.keys = None
        self.client_seq = 0
        self.server_seq = 0
        self.server_identity_pubkey = None
        self.key_id = 1  # current encryption key id (incremented on rekey)

    def _sendall(self, data):
        self.sock.sendall(data)

    def _recvall(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("connection closed")
            buf += chunk
        return buf

    def _recv_frame(self):
        header = self._recvall(HEADER_SIZE)
        length = struct.unpack(">I", header[33:37])[0]
        payload = self._recvall(length) if length > 0 else b""
        return parse_frame(header + payload)

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port))

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def _raw_pubkey(self, key):
        return key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def handshake(self):
        # 1. Generate ephemeral X25519 key + random.
        client_eph = X25519PrivateKey.generate()
        client_random = os.urandom(32)
        client_eph_pub = self._raw_pubkey(client_eph.public_key())
        client_id_pub = self._raw_pubkey(self.identity_pubkey)

        ch = ClientHello(
            version=PROTOCOL_VERSION,
            cipher_suites=[CIPHER_AES256GCM],
            client_random=client_random,
            client_eph_pubkey=client_eph_pub,
            client_identity_pubkey=client_id_pub,
        )
        ch_bytes = ch.marshal()
        self._sendall(build_frame(MSG_CLIENT_HELLO, 0, 0, ch_bytes))

        # 2. Receive ServerHello.
        sh_frame = self._recv_frame()
        assert sh_frame["msg_type"] == MSG_SERVER_HELLO, "expected ServerHello"
        sh = ServerHello.unmarshal(sh_frame["payload"])

        # Optional peer pinning.
        if self.peer_pubkey is not None:
            assert sh.server_identity_pubkey == self.peer_pubkey, \
                "server identity key mismatch (possible MITM)"
        self.server_identity_pubkey = sh.server_identity_pubkey

        # 3. Receive ServerProof.
        sp_frame = self._recv_frame()
        assert sp_frame["msg_type"] == MSG_SERVER_PROOF, "expected ServerProof"
        sp = ServerProof.unmarshal(sp_frame["payload"])

        # 4. Verify server signature over CH || SH.
        server_id_pub = Ed25519PublicKey.from_public_bytes(
            sh.server_identity_pubkey)
        transcript1 = ch_bytes + sh_frame["payload"]
        server_id_pub.verify(sp.signature, transcript1)

        # 5. Derive session keys.
        server_eph_pub = X25519PublicKey.from_public_bytes(
            sh.server_eph_pubkey)
        shared = client_eph.exchange(server_eph_pub)
        self.keys = derive_session_keys(shared, client_random, sh.server_random)
        self.client_seq = 0
        self.server_seq = 0
        self.key_id = 1

        # 6. Send ClientFinished (encrypted) with signature over full transcript.
        full_transcript = ch_bytes + sh_frame["payload"] + sp_frame["payload"]
        client_sig = self.identity_privkey.sign(full_transcript)
        cf_bytes = ClientFinished(client_sig).marshal()
        self._send_encrypted(MSG_CLIENT_FINISHED, cf_bytes)

        # 7. Receive ServerFinished (encrypted).
        sf_payload = self._recv_encrypted()
        sf = ServerFinished.unmarshal(sf_payload)
        assert sf.success, "server rejected handshake"

    def _send_encrypted(self, msg_type, payload):
        self.client_seq += 1
        seq = self.client_seq
        ts = time.time_ns()
        frame_dict = {
            "magic": MAGIC, "version": PROTOCOL_VERSION,
            "msg_type": msg_type, "key_id": self.key_id, "seq": seq, "timestamp": ts,
        }
        aad = header_bytes_for_aad(frame_dict) + self.keys["session_id"]
        nonce = nonce_for_seq(self.keys["client_nonce_prefix"], seq)
        aesgcm = AESGCM(self.keys["client_key"])
        ct = aesgcm.encrypt(nonce, payload, aad)
        self._sendall(build_frame(msg_type, self.key_id, seq, ct, timestamp_ns=ts))

    def _recv_encrypted(self):
        frame = self._recv_frame()
        self.server_seq += 1  # server increments per sent frame
        seq = frame["seq"]
        aad = header_bytes_for_aad(frame) + self.keys["session_id"]
        nonce = nonce_for_seq(self.keys["server_nonce_prefix"], seq)
        aesgcm = AESGCM(self.keys["server_key"])
        return aesgcm.decrypt(nonce, frame["payload"], aad)

    def send_data(self, data):
        self._send_encrypted(MSG_DATA, data)

    def recv_data(self):
        return self._recv_encrypted()

    def rekey(self):
        """Perform an in-band key rotation.

        Sends a Rekey frame (encrypted with the current key), then rotates
        to the new keys derived from prev_traffic_secret || new_random.
        Mirrors the Go InitiateRekey / handleRekey logic.
        """
        new_random = os.urandom(32)
        rk = Rekey(new_key_id=self.key_id + 1, new_random=new_random)
        rk_bytes = rk.marshal()
        # Send rekey frame encrypted under current key.
        self._send_encrypted(MSG_REKEY, rk_bytes)
        # Rotate to new keys immediately.
        new_keys = derive_rekey_keys(self.keys["traffic_secret"], new_random)
        self.keys = new_keys
        self.key_id += 1
        # Seq resets on key rotation (safe because key material changed).
        self.client_seq = 0
        self.server_seq = 0

    # --- Test helpers for attack scenarios ---

    def send_raw_frame(self, frame_bytes):
        """Send a raw (possibly tampered) frame. For attack tests."""
        self._sendall(frame_bytes)

    def build_encrypted_frame_bytes(self, msg_type, payload, seq=None,
                                    timestamp_ns=None, key_id=None):
        """Build an encrypted frame as raw bytes. For attack tests.

        Allows overriding seq, timestamp, and key_id to construct frames
        that violate protocol invariants (replay, expired, wrong key_id).
        """
        if key_id is None:
            key_id = self.key_id
        if seq is None:
            self.client_seq += 1
            seq = self.client_seq
        if timestamp_ns is None:
            timestamp_ns = time.time_ns()
        frame_dict = {
            "magic": MAGIC, "version": PROTOCOL_VERSION,
            "msg_type": msg_type, "key_id": key_id, "seq": seq,
            "timestamp": timestamp_ns,
        }
        aad = header_bytes_for_aad(frame_dict) + self.keys["session_id"]
        nonce = nonce_for_seq(self.keys["client_nonce_prefix"], seq)
        aesgcm = AESGCM(self.keys["client_key"])
        ct = aesgcm.encrypt(nonce, payload, aad)
        return build_frame(msg_type, key_id, seq, ct, timestamp_ns=timestamp_ns)

    def build_encrypted_frame_bytes_with_key(self, msg_type, payload, seq,
                                             key_id, client_key,
                                             client_nonce_prefix, session_id,
                                             timestamp_ns=None):
        """Build an encrypted frame using explicitly provided key material.

        Used for T6 (nonce reuse): encrypt with the OLD key but send under
        a different key_id to simulate nonce/(key,nonce) overlap attempts.
        """
        if timestamp_ns is None:
            timestamp_ns = time.time_ns()
        frame_dict = {
            "magic": MAGIC, "version": PROTOCOL_VERSION,
            "msg_type": msg_type, "key_id": key_id, "seq": seq,
            "timestamp": timestamp_ns,
        }
        aad = header_bytes_for_aad(frame_dict) + session_id
        nonce = nonce_for_seq(client_nonce_prefix, seq)
        aesgcm = AESGCM(client_key)
        ct = aesgcm.encrypt(nonce, payload, aad)
        return build_frame(msg_type, key_id, seq, ct, timestamp_ns=timestamp_ns)
