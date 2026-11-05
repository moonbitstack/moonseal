// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The suite this file implements: the KEM identifier of MLKEM768-X25519
/// (0x647a), HKDF-SHA256 (0x0001) and ChaCha20-Poly1305 (0x0003), laid out the
/// way RFC 9180 §5.1 lays a suite identifier out.
///
/// Those four numbers are the whole of the agreement between two
/// implementations, so they are spelled here rather than derived: a typo in one
/// of them would still produce files, just never ones anybody else opens.
let suite : Bytes = b"HPKE\x64\x7a\x00\x01\x00\x03"

///|
/// SHA-256, as the hash this suite's key schedule is built on.
let sha256 : () -> &@cryptspec.Hash = fn() -> &@cryptspec.Hash {
  @sha2.Hasher::new()
}

///|
/// Two bytes, big-endian, which HPKE puts in front of every length it hashes.
fn u16(value : Int32) -> Bytes {
  Bytes::from_array([(value >> 8).to_byte(), value.to_byte()])
}

///|
/// The key and nonce a base-mode context derives from one shared secret.
pub(all) struct Context {
  key : Bytes
  nonce : Bytes
}

///|
/// HKDF-Extract over the suite's label prefix: the salt is the one the caller
/// gives, and the input keying material is domain-separated before it is
/// extracted.
fn extract(salt : BytesView, label : String, ikm : BytesView) -> Bytes {
  let material = @buffer.Buffer(size_hint=suite.length() + label.length() + 32)
  material.write_bytes(b"HPKE-v1")
  material.write_bytes(suite)
  material.write_bytes(@utf8.encode(label))
  material.write_bytes(ikm)
  @hkdf.extract(material.to_bytes(), sha256, salt~).bytes()
}

///|
/// HKDF-Expand with the same prefix, and the output length in front of it, as
/// RFC 9180 §4 defines `LabeledExpand`.
fn expand(
  prk : BytesView,
  label : String,
  info : BytesView,
  len : Int32,
) -> Bytes {
  let context = @buffer.Buffer(size_hint=suite.length() + label.length() + 40)
  context.write_bytes(u16(len))
  context.write_bytes(b"HPKE-v1")
  context.write_bytes(suite)
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
pub fn context(shared : BytesView, info : BytesView) -> Context {
  let psk_id_hash = extract(b""[:], "psk_id_hash", b""[:])
  let info_hash = extract(b""[:], "info_hash", info)
  let schedule = @buffer.Buffer(size_hint=1 + psk_id_hash.length() * 2)
  schedule.write_byte(b'\x00')
  schedule.write_bytes(psk_id_hash)
  schedule.write_bytes(info_hash)
  let schedule = schedule.to_bytes()
  let secret = extract(shared, "secret", b""[:])
  {
    key: expand(secret, "key", schedule, 32),
    nonce: expand(secret, "base_nonce", schedule, 12),
  }
}

///|
/// Seal one message: the file key, under a context whose sequence number is
/// zero.
pub fn seal(shared : BytesView, info : BytesView, plain : BytesView) -> Bytes {
  let context = context(shared, info)
  let aead = @chachapoly.ChaChaPoly::new(context.key[:]) catch {
    _ => abort("hpke: a 32-byte key is a ChaCha20-Poly1305 key")
  }
  aead.seal(nonce=context.nonce[:], plain~, aad=b""[:])
}

///|
/// The same in reverse, or `None` when the tag does not check out — which is the
/// only thing a caller of a hybrid recipient needs to know about it.
pub fn open(shared : BytesView, info : BytesView, cipher : BytesView) -> Bytes? {
  let context = context(shared, info)
  let aead = @chachapoly.ChaChaPoly::new(context.key[:]) catch {
    _ => abort("hpke: a 32-byte key is a ChaCha20-Poly1305 key")
  }
  return Some(
    aead.open(nonce=context.nonce[:], cipher~, aad=b""[:]) catch {
      _ => return None
    },
  )
}
