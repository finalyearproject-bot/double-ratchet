"""
demo_double_ratchet.py

A NARRATED, STEP-BY-STEP DEMONSTRATION of double_ratchet.py.

This script is for demonstration/teaching purposes only -- it imports the
real DoubleRatchet class from double_ratchet.py (no logic is duplicated
here) and prints every internal value as it changes: root keys, chain
keys, message keys, DH outputs, headers, ciphertexts, and exactly when
and why the DH ratchet fires.

Run it directly:
    python demo_double_ratchet.py

It does NOT touch X3DH -- it simulates X3DH's output the same way the
real test suite does, with a random 32-byte SK and a fresh key pair
standing in for Bob's signed prekey. In the real app, both of those
come from x3dh.py instead.
"""

import os
import binascii
import time

from cryptography.hazmat.primitives.asymmetric import x25519

from double_ratchet import (
    DoubleRatchet,
    DecryptionError,
    header_to_dict,
    header_from_dict,
    bytes_to_b64,
    b64_to_bytes,
    public_key_to_bytes,
)


# ---------------------------------------------------------------------------
# Pretty-printing helpers
# ---------------------------------------------------------------------------

def hexshort(data: bytes, n: int = 16) -> str:
    """Show the first n bytes of data as hex, with an ellipsis if truncated."""
    h = binascii.hexlify(data).decode()
    shown = h[: n * 2]
    suffix = "..." if len(h) > n * 2 else ""
    return f"{shown}{suffix} ({len(data)} bytes)"


def section(title: str):
    print("\n" + "=" * 78)
    print(f" {title}")
    print("=" * 78)


def step(msg: str):
    print(f"\n  -> {msg}")


def detail(label: str, value: str):
    print(f"       {label:<22}: {value}")


def pause(seconds: float = 0.0):
    # Set to a small positive number (e.g. 0.4) if you want the demo to
    # visibly "play out" live during a presentation instead of dumping
    # everything instantly.
    if seconds:
        time.sleep(seconds)


def dump_state(label: str, rs: DoubleRatchet):
    """Print a snapshot of one side's full ratchet state."""
    print(f"\n  [{label}'s internal state]")
    detail("RK (root key)", hexshort(rs.RK))
    detail("DHs (our priv->pub)", hexshort(public_key_to_bytes(rs.DHs.public_key())))
    detail("DHr (their pub)", hexshort(public_key_to_bytes(rs.DHr)) if rs.DHr else "None (not yet received)")
    detail("CKs (sending chain)", hexshort(rs.CKs) if rs.CKs else "None")
    detail("CKr (receiving chain)", hexshort(rs.CKr) if rs.CKr else "None")
    detail("PN / Ns / Nr", f"{rs.PN} / {rs.Ns} / {rs.Nr}")
    detail("Skipped keys stored", str(len(rs.MKSKIPPED)))


def send_message(sender_label, sender, receiver_label, receiver, plaintext: bytes, ad: bytes = b""):
    """
    Encrypts on the sender's ratchet, narrates exactly what happened, then
    decrypts on the receiver's ratchet (simulating it crossing the network
    as JSON) and narrates that too.
    """
    print(f"\n  [{sender_label} encrypts: {plaintext!r}]")
    dhr_before = public_key_to_bytes(sender.DHr) if sender.DHr else None

    header, ciphertext = sender.encrypt(plaintext, ad)

    detail("Message key used", "derived fresh from CKs via HMAC-SHA256, used once, discarded")
    detail("Header dh_pub", hexshort(header["dh_pub"]))
    detail("Header pn / n", f"{header['pn']} / {header['n']}")
    detail("Ciphertext", hexshort(ciphertext))
    detail("Encrypted with", "AES-256-GCM (key=32-byte message key, nonce=constant zero -- safe since key is single-use)")

    # Simulate network transport: serialize to JSON-safe forms and back.
    wire_header = header_to_dict(header)
    wire_ciphertext = bytes_to_b64(ciphertext)
    print(f"       (...travels over the network as JSON: "
          f"header={wire_header}, ciphertext='{wire_ciphertext[:24]}...')")

    received_header = header_from_dict(wire_header)
    received_ciphertext = b64_to_bytes(wire_ciphertext)

    print(f"\n  [{receiver_label} receives and decrypts]")
    dhr_known = public_key_to_bytes(receiver.DHr) if receiver.DHr else None
    new_key_arrived = received_header["dh_pub"] != dhr_known

    if new_key_arrived:
        detail("New DH public key?", "YES -- this header's dh_pub differs from what we have stored")
        detail("Consequence", "DH ratchet will fire: new root key + new receiving chain")
    else:
        detail("New DH public key?", "no -- same chain, symmetric ratchet only")

    plaintext_out = receiver.decrypt(received_header, received_ciphertext, ad)
    detail("Decrypted plaintext", repr(plaintext_out))

    assert plaintext_out == plaintext, "DEMO BUG: decrypted text does not match what was sent!"
    return plaintext_out


# ---------------------------------------------------------------------------
# Main narrated walkthrough
# ---------------------------------------------------------------------------

def main():
    section("PHASE 0: SIMULATED X3DH OUTPUT")
    step("In the real app, x3dh.py hands us two things once the handshake completes:")
    detail("1. SK", "a 32-byte shared secret (identical on both sides)")
    detail("2. Bob's SPK pair", "public half for Alice's session, private half for Bob's session")

    SK = os.urandom(32)
    bob_spk_private = x25519.X25519PrivateKey.generate()
    bob_spk_public = bob_spk_private.public_key()

    detail("Simulated SK", hexshort(SK))
    detail("Simulated Bob SPK (pub)", hexshort(public_key_to_bytes(bob_spk_public)))

    section("PHASE 1: SESSION INITIALIZATION")
    step("Alice is the initiator -- she gets Bob's SPK PUBLIC key and immediately")
    step("generates her own first ratchet key pair, then performs DH #1 herself.")

    alice = DoubleRatchet(SK, bob_spk_public, is_bob=False)
    dump_state("Alice", alice)

    step("Bob is the responder -- he gets his OWN SPK PRIVATE key and does nothing")
    step("else yet. He has no sending chain (CKs=None) until Alice's first message arrives.")

    bob = DoubleRatchet(SK, bob_spk_private, is_bob=True)
    dump_state("Bob", bob)

    step("Notice: Alice already has a CKs (sending chain) and an RK derived from a real")
    step("DH output. Bob's RK is still just the raw SK -- he hasn't ratcheted yet.")

    section("PHASE 2: ALICE SENDS THE FIRST MESSAGE (triggers Bob's first DH ratchet)")
    send_message("Alice", alice, "Bob", bob, b"Hi Bob, this is Alice's very first message.")
    dump_state("Bob (after receiving)", bob)
    step("Bob's DHr is now Alice's public key, and his RK/CKr were just derived.")
    step("Bob still has no CKs of his own yet -- he can't send until HE replies,")
    step("which will generate HIS first ratchet key pair.")

    section("PHASE 3: BOB REPLIES (triggers Alice's second DH ratchet)")
    send_message("Bob", bob, "Alice", alice, b"Hey Alice! Got your message loud and clear.")
    dump_state("Alice (after receiving)", alice)
    step("Both sides have now performed a DH ratchet step. From here on, every time")
    step("the conversation 'turns' (the other person replies), a fresh DH exchange")
    step("happens automatically and the root key is re-randomized.")

    section("PHASE 4: SEVERAL MESSAGES IN A ROW (pure symmetric ratchet, no DH ratchet)")
    step("Alice sends 3 messages without waiting for a reply. Watch CKs change each")
    step("time via the symmetric ratchet (KDF_CK) -- DHs/DHr stay the same.")

    for i in range(3):
        print(f"\n  --- message {i + 1} of 3 ---")
        ck_before = alice.CKs
        send_message("Alice", alice, "Bob", bob, f"Quick message #{i + 1}, no reply needed.".encode())
        print(f"       CKs changed: {hexshort(ck_before)} -> {hexshort(alice.CKs)}")

    section("PHASE 5: OUT-OF-ORDER DELIVERY (network delay simulation)")
    step("Alice sends two messages back-to-back. We deliver them to Bob in REVERSE")
    step("order, simulating a network that re-orders packets.")

    h_first, c_first = alice.encrypt(b"This was sent FIRST but will ARRIVE SECOND.")
    h_second, c_second = alice.encrypt(b"This was sent SECOND but will ARRIVE FIRST.")

    print(f"\n  [Alice sent message n={h_first['n']} then n={h_second['n']}]")
    print(f"\n  [Delivering n={h_second['n']} to Bob FIRST]")
    out2 = bob.decrypt(h_second, c_second)
    detail("Bob decrypted", repr(out2))
    detail("Bob's MKSKIPPED now holds", f"{len(bob.MKSKIPPED)} key(s) -- saved for message n={h_first['n']}")

    print(f"\n  [Delivering n={h_first['n']} to Bob LATE]")
    out1 = bob.decrypt(h_first, c_first)
    detail("Bob decrypted", repr(out1))
    detail("Bob's MKSKIPPED now holds", f"{len(bob.MKSKIPPED)} key(s) -- the stored key was consumed and removed")

    section("PHASE 6: TAMPERED MESSAGE IS REJECTED")
    step("Alice sends a normal message. We flip one bit in the ciphertext before")
    step("Bob receives it, simulating an attacker or network corruption.")

    h, c = alice.encrypt(b"This message will be corrupted in transit.")
    tampered = bytearray(c)
    tampered[-1] ^= 0xFF
    detail("Original (last 8 bytes)", binascii.hexlify(c[-8:]).decode())
    detail("Tampered (last 8 bytes)", binascii.hexlify(bytes(tampered)[-8:]).decode() + "  <- one bit flipped here")
    detail("Detected by", "AES-GCM's built-in 16-byte authentication tag (part of the ciphertext) -- not a separate check")

    try:
        bob.decrypt(h, bytes(tampered))
        print("       UNEXPECTED: tampered message was accepted! (this should never happen)")
    except DecryptionError as e:
        print(f"       REJECTED as expected (AES-GCM tag verification failed) -> {e}")

    section("PHASE 7: SESSION PERSISTENCE (simulating Flask's statelessness)")
    step("Flask doesn't keep Python objects alive between HTTP requests. Each")
    step("request must reload the session from a database via to_dict()/from_dict().")

    state = alice.to_dict()
    print(f"\n  [Alice's state serialized to a DB-storable dict with keys:]")
    print(f"       {list(state.keys())}")

    step("Discarding the live 'alice' object and reconstructing it from that dict")
    step("only -- exactly as a second Flask worker handling the next request would.")

    alice = DoubleRatchet.from_dict(state)
    send_message("Alice (reloaded)", alice, "Bob", bob, b"Still working after a simulated server restart.")

    section("PHASE 8: FINAL SECURITY GUARANTEES, DEMONSTRATED ABOVE")
    print("""
  Forward secrecy:
      Every message used a DIFFERENT message key (Phase 4 showed CKs
      changing each send). Stealing today's CKs cannot recompute
      yesterday's message keys, because KDF_CK is one-way (HMAC).

  Future secrecy / self-healing:
      Every time the conversation turned (Phases 2 and 3), a brand new
      DH key pair was generated and a fresh root key was derived. Even
      if a chain key were stolen, the next DH ratchet step heals the
      session with entropy the attacker cannot predict.

  Out-of-order resilience:
      Phase 5 showed messages decrypting correctly even when delivered
      out of sequence, without breaking the chain for subsequent messages.

  Authentication:
      Phase 6 showed a single flipped bit causing total rejection via
      AES-GCM's authentication tag -- not silent corruption.
""")

    section("DEMO COMPLETE")


if __name__ == "__main__":
    main()
