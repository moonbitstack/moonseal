// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Which key encapsulation a suite runs on.
///
/// The three are the ones the age format names: X-Wing for the post-quantum
/// recipient, DHKEM over P-256 for a tagged one, and ML-KEM-768 hybridised with
/// P-256 for the tagged one that has to outlive a quantum computer. Each is a
/// number, and the number is the whole of the agreement between two
/// implementations: a typo in one would still produce files, just never ones
/// anybody else opens.
#derive(Eq, Debug)
pub(all) enum Kem {
  /// MLKEM768-X25519, the hybrid X-Wing KEM (0x647a).
  XWing
  /// DHKEM(P-256, HKDF-SHA256) (0x0010).
  P256
  /// MLKEM768-P256, an ML-KEM-768 secret combined with a P-256 one (0x0050).
  Mlkem768P256
}

///|
pub extend Kem with Eq::{equal, not_equal}

///|
pub extend Kem with Debug::{to_repr}

///|
/// The number a suite identifier carries for this KEM.
fn Kem::id(self : Kem) -> Int32 {
  match self {
    XWing => 0x647a
    P256 => 0x0010
    Mlkem768P256 => 0x0050
  }
}

///|
/// Two bytes, big-endian, which HPKE puts in front of every length it hashes.
fn u16(value : Int32) -> Bytes {
  Bytes::from_array([(value >> 8).to_byte(), value.to_byte()])
}

///|
/// SHA-256, as the hash these suites' key schedules are built on.
let sha256 : () -> &@cryptspec.Hash = fn() -> &@cryptspec.Hash {
  @sha2.Hasher::new()
}

///|
/// The suite identifier of RFC 9180 §5.1: the letters `HPKE`, the KEM's number,
/// and the KDF and AEAD every suite here shares — HKDF-SHA256 (0x0001) and
/// ChaCha20-Poly1305 (0x0003).
fn suite(kem : Kem) -> Bytes {
  let out = @buffer.Buffer(size_hint=10)
  out.write_bytes(b"HPKE")
  out.write_bytes(u16(kem.id()))
  out.write_bytes(b"\x00\x01\x00\x03")
  out.to_bytes()
}

///|
/// The identifier a KEM's own labelled functions run under, which RFC 9180 §4
/// spells as the letters `KEM` and the KEM's number.
fn kem_suite(kem : Kem) -> Bytes {
  let out = @buffer.Buffer(size_hint=5)
  out.write_bytes(b"KEM")
  out.write_bytes(u16(kem.id()))
  out.to_bytes()
}

///|
/// The length of a secret key at every KEM here: a scalar for the curves, a seed
/// for the hybrids, and thirty-two bytes either way.
let seed_size : Int32 = 32

///|
/// The one-stage labelled derivation of draft-ietf-hpke-pq, which is
/// `DeriveKeyPair` for the KEMs that define their own hash: SHAKE256 over the
/// input keying material, the letters `HPKE-v1`, the suite, the label and its
/// length, the output length, and a context.
fn labeled_derive(
  kem : Kem,
  seed : BytesView,
  label : String,
  len : Int32,
) -> Bytes {
  let material = @buffer.Buffer(size_hint=seed.length() + label.length() + 32)
  material.write_bytes(seed)
  material.write_bytes(b"HPKE-v1")
  material.write_bytes(kem_suite(kem))
  material.write_bytes(u16(label.length()))
  material.write_bytes(@utf8.encode(label))
  material.write_bytes(u16(len))
  @sha3.shake256(material.to_bytes(), len)
}

///|
/// The key and nonce a base-mode context derives from one shared secret.
pub(all) struct Context {
  key : Bytes
  nonce : Bytes
}

///|
/// One encapsulation: what goes into the stanza, and the secret both sides come
/// out with.
pub(all) struct Encapsulated {
  enc : Bytes
  shared : Bytes
}

///|
/// The public key behind a secret, in the shape the KEM writes it: what a sender
/// needs, and what a reader keeps no copy of.
pub fn public_of(kem : Kem, secret : BytesView) -> Bytes raise @spec.Refused {
  match kem {
    XWing => xwing_public_of(secret)
    P256 => p256_public_of(secret)
    Mlkem768P256 => hybrid_public_of(secret)
  }
}

///|
/// Encapsulate to a public key: one ephemeral secret, and the encapsulation that
/// lets the other side reach the same shared secret.
pub fn encapsulate(
  kem : Kem,
  public : BytesView,
  random : &@moonseed.Source,
) -> Encapsulated raise @spec.Refused {
  match kem {
    XWing => xwing_encapsulate(public, random)
    P256 => p256_encapsulate(public, random)
    Mlkem768P256 => hybrid_encapsulate(public, random)
  }
}

///|
/// The secret behind an encapsulation, from the secret key the reader holds.
pub fn decapsulate(
  kem : Kem,
  secret : BytesView,
  enc : BytesView,
) -> Bytes raise @spec.Refused {
  match kem {
    XWing => xwing_decapsulate(secret, enc)
    P256 => p256_decapsulate(secret, enc)
    Mlkem768P256 => hybrid_decapsulate(secret, enc)
  }
}

///|
/// A secret key derived from a seed, by HPKE's `DeriveKeyPair` (RFC 9180 §7.1.3).
///
/// A recipient type whose identity has no written form needs one way for two
/// implementations to arrive at the same key from the same bytes, and this is
/// the one HPKE already defines. It is thirty-two bytes out for all three KEMs.
pub fn from_seed(kem : Kem, seed : BytesView) -> Bytes raise @spec.Refused {
  match kem {
    XWing => xwing_from_seed(seed)
    P256 => p256_from_seed(seed)
    Mlkem768P256 => hybrid_from_seed(seed)
  }
}

///|
/// The length of the public key a KEM takes.
pub fn public_size(kem : Kem) -> Int32 {
  match kem {
    XWing => 1184 + 32
    P256 => 65
    Mlkem768P256 => 1184 + 65
  }
}

///|
/// The length of an encapsulation: what a stanza carries as its last argument,
/// and what the reader hands back to the KEM.
pub fn enc_size(kem : Kem) -> Int32 {
  match kem {
    XWing => 1088 + 32
    P256 => 65
    Mlkem768P256 => 1088 + 65
  }
}

///|
/// HKDF-Extract over the suite's label prefix: the salt is the one the caller
/// gives, and the input keying material is domain-separated before it is
/// extracted.
fn extract(
  id : BytesView,
  salt : BytesView,
  label : String,
  ikm : BytesView,
) -> Bytes {
  let material = @buffer.Buffer(size_hint=id.length() + label.length() + 32)
  material.write_bytes(b"HPKE-v1")
  material.write_bytes(id)
  material.write_bytes(@utf8.encode(label))
  material.write_bytes(ikm)
  @hkdf.extract(material.to_bytes(), sha256, salt~).bytes()
}

///|
/// HKDF-Expand with the same prefix, and the output length in front of it, as
/// RFC 9180 §4 defines `LabeledExpand`.
fn expand(
  id : BytesView,
  prk : BytesView,
  label : String,
  info : BytesView,
  len : Int32,
) -> Bytes {
  let context = @buffer.Buffer(size_hint=id.length() + label.length() + 40)
  context.write_bytes(u16(len))
  context.write_bytes(b"HPKE-v1")
  context.write_bytes(id)
  context.write_bytes(@utf8.encode(label))
  context.write_bytes(info)
  @hkdf.expand(@hkdf.Prk::new(prk, sha256), info=context.to_bytes(), len~)
}

///|
/// The key schedule of base mode, for a shared secret and the sender's `info`.
///
/// There is no pre-shared key, so the pre-shared key identifier hashes the empty
/// string and the secret is extracted from the KEM's output alone; the rest is
/// the two expansions every HPKE mode shares.
pub fn context(kem : Kem, shared : BytesView, info : BytesView) -> Context {
  let id = suite(kem)
  let psk_id_hash = extract(id, b""[:], "psk_id_hash", b""[:])
  let info_hash = extract(id, b""[:], "info_hash", info)
  let schedule = @buffer.Buffer(size_hint=1 + psk_id_hash.length() * 2)
  schedule.write_byte(b'\x00')
  schedule.write_bytes(psk_id_hash)
  schedule.write_bytes(info_hash)
  let schedule = schedule.to_bytes()
  let secret = extract(id, shared, "secret", b""[:])
  {
    key: expand(id, secret, "key", schedule, 32),
    nonce: expand(id, secret, "base_nonce", schedule, 12),
  }
}

///|
/// Seal one message: the file key, under a context whose sequence number is
/// zero.
pub fn seal(
  kem : Kem,
  shared : BytesView,
  info : BytesView,
  plain : BytesView,
) -> Bytes {
  let context = context(kem, shared, info)
  let aead = @chachapoly.ChaChaPoly::new(context.key[:]) catch {
    _ => abort("hpke: a 32-byte key is a ChaCha20-Poly1305 key")
  }
  aead.seal(nonce=context.nonce[:], plain~, aad=b""[:])
}

///|
/// The same in reverse, or `None` when the tag does not check out — which is the
/// only thing a caller of a hybrid recipient needs to know about it.
pub fn open(
  kem : Kem,
  shared : BytesView,
  info : BytesView,
  cipher : BytesView,
) -> Bytes? {
  let context = context(kem, shared, info)
  let aead = @chachapoly.ChaChaPoly::new(context.key[:]) catch {
    _ => abort("hpke: a 32-byte key is a ChaCha20-Poly1305 key")
  }
  return Some(
    aead.open(nonce=context.nonce[:], cipher~, aad=b""[:]) catch {
      _ => return None
    },
  )
}
