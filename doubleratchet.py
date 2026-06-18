import os
import base64
import logging
from typing import Optional, Tuple, Dict, Any

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidTag

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
# This is a library module — it never configures handlers or levels itself.
# The Flask app (app.py) owns all logging configuration. To see ratchet
# debug traces during development, add this to app.py:
#
#   import logging
#   logging.getLogger("double_ratchet").setLevel(logging.DEBUG)
#
logger = logging.getLogger("double_ratchet")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum number of out-of-order messages we will buffer keys for per chain.
# Prevents a malicious/buggy peer from forcing unbounded memory growth by
# sending a message with a huge "n" and never sending the intermediate ones.
MAX_SKIP = 1000

NONCE_LEN = 12   # AES-GCM standard nonce length
KEY_LEN = 32     # 256-bit keys throughout (RK, CK, MK all 32 bytes)


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class DoubleRatchetError(Exception):
    """Base class for all errors raised by this module."""


class DecryptionError(DoubleRatchetError):
    """
    Raised when a message fails to decrypt/authenticate.

    This can happen for several reasons: the message was tampered with,
    corrupted in transit, replayed, or arrived with a stale/invalid key.
    The Flask server should catch this and return a 4xx response rather
    than letting the worker crash.
    """


class TooManySkippedMessagesError(DoubleRatchetError):
    """Raised when a peer's message implies skipping more than MAX_SKIP keys."""


# ---------------------------------------------------------------------------
# Serialization helpers (for the server team)
# ---------------------------------------------------------------------------

def bytes_to_b64(data: bytes) -> str:
    """Convert raw bytes to a URL-safe base64 string for JSON transport."""
    return base64.b64encode(data).decode("ascii")


def b64_to_bytes(data: str) -> bytes:
    """Convert a base64 string (from JSON) back to raw bytes."""
    return base64.b64decode(data)


def header_to_dict(header: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert a ratchet header (as produced by DoubleRatchet.encrypt) into a
    plain dict containing only JSON-serializable types (strings/ints).

    Use this immediately before passing the header to Flask's jsonify().
    """
    return {
        "dh_pub": bytes_to_b64(header["dh_pub"]),
        "pn": header["pn"],
        "n": header["n"],
    }


def header_from_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert a JSON-decoded header dict (with base64 dh_pub) back into the
    raw-bytes form expected by DoubleRatchet.decrypt.
    """
    return {
        "dh_pub": b64_to_bytes(data["dh_pub"]),
        "pn": int(data["pn"]),
        "n": int(data["n"]),
    }


def public_key_to_bytes(public_key: x25519.X25519PublicKey) -> bytes:
    """Serialize an X25519 public key object to raw bytes (32 bytes)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def public_key_from_bytes(data: bytes) -> x25519.X25519PublicKey:
    """Deserialize raw bytes (32 bytes) back into an X25519 public key object."""
    return x25519.X25519PublicKey.from_public_bytes(data)


# ---------------------------------------------------------------------------
# The Double Ratchet
# ---------------------------------------------------------------------------

class DoubleRatchet:
    """
    Holds the complete ratchet state for one side of a conversation:
    Root Key, sending/receiving chain keys, DH ratchet key pairs,
    message counters, and skipped-message-key storage.

    One instance of this class = one ongoing conversation session with
    one other user. If your app supports multiple simultaneous chats,
    the server should keep one DoubleRatchet instance per (user, peer)
    pair (typically pickled/serialized into a database between requests --
    see notes at the bottom of this file).
    """

    # -------------------------------------------------------------------
    # 1. INITIALIZATION
    # -------------------------------------------------------------------
    def __init__(
        self,
        shared_secret: bytes,
        dh_key: Any,
        is_bob: bool = False,
    ):
        """
        Initialize ratchet state immediately after X3DH completes.

        Args:
            shared_secret: The 32-byte SK produced by X3DH. Same value on
                both sides.
            dh_key:
                - If is_bob=False (you are Alice / the initiator):
                  pass Bob's initial DH ratchet PUBLIC key
                  (x25519.X25519PublicKey).
                - If is_bob=True (you are Bob / the responder):
                  pass YOUR OWN initial DH ratchet PRIVATE key
                  (x25519.X25519PrivateKey) -- the one whose public part
                  was published in your prekey bundle.
            is_bob: True if this instance represents Bob (the responder).

        Raises:
            ValueError: if shared_secret is not exactly 32 bytes, or if
                dh_key is not the expected key type for the given role.
        """
        if not isinstance(shared_secret, bytes) or len(shared_secret) != KEY_LEN:
            raise ValueError(
                f"shared_secret must be exactly {KEY_LEN} bytes, "
                f"got {type(shared_secret)} of length "
                f"{len(shared_secret) if hasattr(shared_secret, '__len__') else 'unknown'}"
            )

        # Skipped-message-key store: maps (dh_pub_bytes, message_number) -> message_key
        self.MKSKIPPED: Dict[Tuple[bytes, int], bytes] = {}

        self.PN = 0  # Number of messages in the previous sending chain
        self.Ns = 0  # Messages sent in the current sending chain
        self.Nr = 0  # Messages received in the current receiving chain

        if is_bob:
            if not isinstance(dh_key, x25519.X25519PrivateKey):
                raise ValueError(
                    "Bob must initialize with his own X25519PrivateKey "
                    "(the one whose public key was used in his prekey bundle)."
                )
            # Bob does not yet know Alice's first ratchet key, and has not
            # yet sent anything, so CKs/CKr/DHr all start empty. The first
            # _dh_ratchet() call (triggered by Alice's first message) will
            # populate these.
            self.DHs = dh_key
            self.DHr: Optional[x25519.X25519PublicKey] = None
            self.RK = shared_secret
            self.CKs: Optional[bytes] = None
            self.CKr: Optional[bytes] = None
        else:
            if not isinstance(dh_key, x25519.X25519PublicKey):
                raise ValueError(
                    "Alice must initialize with Bob's X25519PublicKey "
                    "(from his prekey bundle, as used in X3DH)."
                )
            # Alice generates her first ratchet key pair immediately and
            # performs the first DH step right away, so she can send a
            # message before Bob has replied.
            self.DHs = self._generate_dh()
            self.DHr = dh_key

            dh_out = self._dh(self.DHs, self.DHr)
            self.RK, self.CKs = self._kdf_rk(shared_secret, dh_out)
            self.CKr = None

    # -------------------------------------------------------------------
    # 2. CRYPTOGRAPHIC PRIMITIVES
    # -------------------------------------------------------------------

    @staticmethod
    def _generate_dh() -> x25519.X25519PrivateKey:
        """Generate a new X25519 ratchet key pair (returns the private key)."""
        return x25519.X25519PrivateKey.generate()

    @staticmethod
    def _dh(
        private_key: x25519.X25519PrivateKey,
        public_key: x25519.X25519PublicKey,
    ) -> bytes:
        """ECDH: local private key + remote public key -> shared secret bytes."""
        return private_key.exchange(public_key)

    @staticmethod
    def _kdf_rk(rk: bytes, dh_out: bytes) -> Tuple[bytes, bytes]:
        """
        DH ratchet step. Old root key + fresh DH output -> (new root key,
        new chain key), via HKDF-SHA256. This is what injects fresh
        randomness into the chain whenever the conversation 'turns'.
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=2 * KEY_LEN,  # 32 bytes RK + 32 bytes CK
            salt=rk,
            info=b"DoubleRatchet-RootChain",
        )
        derived = hkdf.derive(dh_out)
        return derived[:KEY_LEN], derived[KEY_LEN:]

    @staticmethod
    def _kdf_ck(ck: bytes) -> Tuple[bytes, bytes]:
        """
        Symmetric ratchet step. Current chain key -> (next chain key,
        message key for THIS message), via two independent HMAC-SHA256
        computations over the chain key. Runs once per message sent/received.
        """
        h_mk = hmac.HMAC(ck, hashes.SHA256())
        h_mk.update(b"\x01")
        message_key = h_mk.finalize()

        h_ck = hmac.HMAC(ck, hashes.SHA256())
        h_ck.update(b"\x02")
        next_chain_key = h_ck.finalize()

        return next_chain_key, message_key

    # -------------------------------------------------------------------
    # 3. OUT-OF-ORDER MESSAGE HANDLING
    # -------------------------------------------------------------------

    def _try_skipped_message_keys(self, header: Dict[str, Any]) -> Optional[bytes]:
        """Return and remove a previously-stored key for this message, if any."""
        dh_pub_bytes = header["dh_pub"]
        msg_num = header["n"]

        key = (dh_pub_bytes, msg_num)
        if key in self.MKSKIPPED:
            mk = self.MKSKIPPED.pop(key)
            logger.debug("Found stored key for skipped message #%d", msg_num)
            return mk
        return None

    def _skip_message_keys(self, until: int) -> None:
        """
        Advance the receiving chain up to (but not including) message
        number `until`, storing each intermediate message key so it can
        be used later if that message arrives out of order.
        """
        if until < self.Nr:
            # Nothing to skip -- 'until' is in the past relative to Nr.
            return

        if until - self.Nr > MAX_SKIP:
            raise TooManySkippedMessagesError(
                f"Refusing to skip {until - self.Nr} messages "
                f"(limit is {MAX_SKIP}). Possible attack or desync."
            )

        if self.CKr is not None:
            dh_pub_bytes = public_key_to_bytes(self.DHr)
            while self.Nr < until:
                self.CKr, mk = self._kdf_ck(self.CKr)
                self.MKSKIPPED[(dh_pub_bytes, self.Nr)] = mk
                self.Nr += 1

    # -------------------------------------------------------------------
    # 4. DIFFIE-HELLMAN RATCHET
    # -------------------------------------------------------------------

    def _dh_ratchet(self, header: Dict[str, Any]) -> None:
        """
        Triggered when an incoming message carries a new DH public key
        from the peer (i.e. the conversation has "turned"). Performs two
        DH exchanges to derive a fresh receiving chain and a fresh sending
        chain, injecting new entropy into the root key in the process.
        """
        logger.debug("DH ratchet triggered")

        self.PN = self.Ns
        self.Ns = 0
        self.Nr = 0

        self.DHr = public_key_from_bytes(header["dh_pub"])

        # New receiving chain, derived from (old RK, DH(our old key, their new key))
        dh_out_receive = self._dh(self.DHs, self.DHr)
        self.RK, self.CKr = self._kdf_rk(self.RK, dh_out_receive)
        logger.debug("New receiving chain established")

        # New sending chain: generate a fresh key pair of our own, then
        # derive from (new RK, DH(our new key, their new key))
        self.DHs = self._generate_dh()
        dh_out_send = self._dh(self.DHs, self.DHr)
        self.RK, self.CKs = self._kdf_rk(self.RK, dh_out_send)
        logger.debug("New sending chain established")

    # -------------------------------------------------------------------
    # 5. ENCRYPT / DECRYPT API
    # -------------------------------------------------------------------

    @staticmethod
    def _build_associated_data(header: Dict[str, Any], associated_data: bytes) -> bytes:
        """
        Bind the header fields into the AEAD associated data, so that an
        attacker cannot tamper with dh_pub/pn/n without invalidating the
        authentication tag.
        """
        header_bytes = (
            header["dh_pub"]
            + header["pn"].to_bytes(4, "big")
            + header["n"].to_bytes(4, "big")
        )
        return associated_data + header_bytes

    def encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> Tuple[Dict[str, Any], bytes]:
        """
        Encrypt one outgoing message.

        Args:
            plaintext: The message bytes to encrypt (e.g. utf-8 encoded text).
            associated_data: Extra data to authenticate but not encrypt
                (e.g. sender/recipient IDs from X3DH's AD). Optional.

        Returns:
            (header, ciphertext)
                header: dict with 'dh_pub' (bytes), 'pn' (int), 'n' (int).
                    Pass through header_to_dict() before sending as JSON.
                ciphertext: encrypted + authenticated bytes.
                    Base64-encode before sending as JSON.

        Note on nonce: AES-GCM uses a constant zero nonce here. This is
        safe — and is exactly what the Signal spec prescribes — because the
        ratchet guarantees each message key (mk) is used for exactly one
        encryption. AES-GCM only requires nonce uniqueness per key, and
        since the key itself is always fresh, the nonce can safely be
        constant. Using os.urandom() here would add 12 bytes of overhead
        per message for zero additional security in this construction.

        Raises:
            DoubleRatchetError: if encrypt is called before the sending
                chain has been established (should not happen in normal
                use -- Bob must wait for Alice's first message before he
                can send).
        """
        if self.CKs is None:
            raise DoubleRatchetError(
                "Sending chain not yet established. "
                "Bob must wait to receive Alice's first message before "
                "he can send (this is normal -- it triggers the first "
                "DH ratchet on Bob's side)."
            )

        self.CKs, mk = self._kdf_ck(self.CKs)

        header = {
            "dh_pub": public_key_to_bytes(self.DHs.public_key()),
            "pn": self.PN,
            "n": self.Ns,
        }
        self.Ns += 1

        ad_combined = self._build_associated_data(header, associated_data)

        # Constant zero nonce — safe because mk is always single-use.
        aesgcm = AESGCM(mk)
        nonce = b"\x00" * NONCE_LEN
        ciphertext = aesgcm.encrypt(nonce, plaintext, ad_combined)

        logger.debug("Encrypted message n=%d pn=%d", header["n"], header["pn"])
        return header, ciphertext

    def decrypt(self, header: Dict[str, Any], ciphertext: bytes, associated_data: bytes = b"") -> bytes:
        """
        Decrypt one incoming message.

        Args:
            header: dict with 'dh_pub' (bytes), 'pn' (int), 'n' (int).
                Use header_from_dict() if it came from JSON.
            ciphertext: encrypted bytes as produced by encrypt().
                Use b64_to_bytes() if it came from JSON.
            associated_data: Must match the value the sender used.

        Returns:
            The decrypted plaintext bytes.

        Raises:
            DecryptionError: if authentication fails (tampered/corrupted
                message, or wrong/stale key). The ratchet state is left
                unmodified in this case, EXCEPT for any skipped-key
                bookkeeping that occurred while catching up to this
                message's position -- this matches the reference Signal
                algorithm and is safe because skipped keys for messages
                that were never successfully decrypted are simply unused.
            TooManySkippedMessagesError: if the message implies skipping
                more keys than MAX_SKIP allows.
        """
        mk = self._try_skipped_message_keys(header)

        if mk is None:
            current_dhr_bytes = (
                public_key_to_bytes(self.DHr) if self.DHr is not None else None
            )

            if header["dh_pub"] != current_dhr_bytes:
                self._skip_message_keys(header["pn"])
                self._dh_ratchet(header)

            self._skip_message_keys(header["n"])

            self.CKr, mk = self._kdf_ck(self.CKr)
            self.Nr += 1
            logger.debug("Decrypting message n=%d", header["n"])
        else:
            logger.debug("Using stored key for skipped message n=%d", header["n"])

        # Constant zero nonce — safe because mk is always single-use.
        nonce = b"\x00" * NONCE_LEN
        ad_combined = self._build_associated_data(header, associated_data)

        aesgcm = AESGCM(mk)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, ad_combined)
        except InvalidTag as exc:
            raise DecryptionError(
                "Message failed authentication: it may have been "
                "tampered with, corrupted in transit, or encrypted "
                "with a different key."
            ) from exc

        return plaintext

    # -------------------------------------------------------------------
    # 6. STATE PERSISTENCE (for the server team)
    # -------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialize the full ratchet state to a JSON-safe dict, for storing
        in a database between HTTP requests (Flask is stateless per
        request -- this object will not survive between calls unless you
        persist it).

        WARNING: this dict contains private key material (DHs) and chain
        keys. Store it securely (encrypted at rest), exactly as you would
        any other long-term secret.
        """
        priv_bytes = self.DHs.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

        return {
            "RK": bytes_to_b64(self.RK),
            "DHs_priv": bytes_to_b64(priv_bytes),
            "DHr_pub": bytes_to_b64(public_key_to_bytes(self.DHr)) if self.DHr else None,
            "CKs": bytes_to_b64(self.CKs) if self.CKs else None,
            "CKr": bytes_to_b64(self.CKr) if self.CKr else None,
            "PN": self.PN,
            "Ns": self.Ns,
            "Nr": self.Nr,
            "MKSKIPPED": [
                {"dh_pub": bytes_to_b64(k[0]), "n": k[1], "mk": bytes_to_b64(v)}
                for k, v in self.MKSKIPPED.items()
            ],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DoubleRatchet":
        """
        Reconstruct a DoubleRatchet instance from a dict produced by
        to_dict(). Bypasses __init__'s X3DH-specific validation since we
        are restoring an already-running session, not starting one.
        """
        obj = cls.__new__(cls)

        obj.RK = b64_to_bytes(data["RK"])
        obj.DHs = x25519.X25519PrivateKey.from_private_bytes(
            b64_to_bytes(data["DHs_priv"])
        )
        obj.DHr = (
            public_key_from_bytes(b64_to_bytes(data["DHr_pub"]))
            if data["DHr_pub"] is not None
            else None
        )
        obj.CKs = b64_to_bytes(data["CKs"]) if data["CKs"] is not None else None
        obj.CKr = b64_to_bytes(data["CKr"]) if data["CKr"] is not None else None
        obj.PN = data["PN"]
        obj.Ns = data["Ns"]
        obj.Nr = data["Nr"]
        obj.MKSKIPPED = {
            (b64_to_bytes(item["dh_pub"]), item["n"]): b64_to_bytes(item["mk"])
            for item in data["MKSKIPPED"]
        }
        return obj


# ---------------------------------------------------------------------------
# Self-test (runs only when this file is executed directly)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Configure a handler here — this is an entry point, not a library import.
    # app.py does this for the server; here we do it for the test runner.
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("[%(name)s] %(message)s"))
    logger.addHandler(_handler)
    logger.setLevel(logging.DEBUG)

    # --- Simulate X3DH output ---
    # In the real app, shared_secret comes from x3dh.py.
    # bob_initial_private is Bob's SPK private key (also from x3dh.py).
    shared_secret_from_x3dh = os.urandom(32)

    bob_initial_private = x25519.X25519PrivateKey.generate()
    bob_initial_public = bob_initial_private.public_key()

    # Initiator role (Alice) gets Bob's SPK public key.
    # Responder role (Bob) gets his own SPK private key.
    alice = DoubleRatchet(shared_secret_from_x3dh, bob_initial_public, is_bob=False)
    bob   = DoubleRatchet(shared_secret_from_x3dh, bob_initial_private, is_bob=True)

    print("\n--- Test 1: Basic exchange + DH ratchet trigger ---")
    h1, c1 = alice.encrypt(b"Hello! This is the first message.")
    print("Bob decrypted:", bob.decrypt(h1, c1).decode())
    h2, c2 = bob.encrypt(b"Got it! Reply triggers DH ratchet.")
    print("Alice decrypted:", alice.decrypt(h2, c2).decode())

    print("\n--- Test 2: Sequential messages (symmetric ratchet) ---")
    for i in range(5):
        h, c = alice.encrypt(f"Sequential message {i}".encode())
        print(f"  [{i}]", bob.decrypt(h, c).decode())

    print("\n--- Test 3: Out-of-order delivery ---")
    hA, cA = alice.encrypt(b"Message A (sent first)")
    hB, cB = alice.encrypt(b"Message B (sent second)")
    print("B arrives first  :", bob.decrypt(hB, cB).decode())
    print("A arrives later  :", bob.decrypt(hA, cA).decode())

    print("\n--- Test 4: Tampered ciphertext is rejected ---")
    h, c = alice.encrypt(b"Authentic message")
    tampered = bytearray(c)
    tampered[-1] ^= 0xFF   # flip one byte in the AES-GCM authentication tag
    try:
        bob.decrypt(h, bytes(tampered))
        print("FAIL: tampered message was accepted!")
    except DecryptionError as e:
        print("OK: rejected ->", e)

    print("\n--- Test 5: JSON serialization round-trip ---")
    h, c = alice.encrypt(b"This crosses the network as JSON")
    h_json = header_to_dict(h)       # header  → JSON-safe dict
    c_json = bytes_to_b64(c)         # bytes   → base64 string
    # ---- network boundary ----
    h_back = header_from_dict(h_json)
    c_back = b64_to_bytes(c_json)
    print("Bob decrypted:", bob.decrypt(h_back, c_back).decode())

    print("\n--- Test 6: Session persistence (to_dict / from_dict) ---")
    # Serialize, discard the live object, reconstruct — exactly what
    # app.py must do between HTTP requests (Flask is stateless per request).
    alice = DoubleRatchet.from_dict(alice.to_dict())
    h, c = alice.encrypt(b"First message after session reload")
    print("Bob decrypted:", bob.decrypt(h, c).decode())

    print("\n--- Test 7: 200-message stress test with periodic replies ---")
    for i in range(200):
        h, c = alice.encrypt(f"Stress {i}".encode())
        bob.decrypt(h, c)
        if i % 20 == 0:   # Bob replies every 20 messages → triggers DH ratchet
            h2, c2 = bob.encrypt(f"Ack {i}".encode())
            alice.decrypt(h2, c2)
    print("200-message stress test passed.")

    print("\nAll tests passed.")