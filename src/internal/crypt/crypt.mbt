// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// SHA-256, as this library's hash of choice in a call that wants one.
let sha256 : () -> &@spec.Hash = fn() -> &@spec.Hash { @sha2.Hasher::new() }

///|
/// The size of a ChaCha20-Poly1305 key and of an X25519 key, which happen to be
/// the same number and are not the same thing.
pub let key_size : Int32 = 32

///|
/// The size of an authentication tag, and so of the overhead every chunk pays.
pub let tag_size : Int32 = 16

///|
/// HKDF-SHA-256, with the salt and the context spelled out.
pub fn hkdf(
  ikm : BytesView,
  salt : BytesView,
  info : BytesView,
  len~ : Int32,
) -> Bytes {
  @hkdf.key(ikm, sha256, salt~, info~, len~)
}

///|
/// HMAC-SHA-256.
pub fn hmac(key : BytesView, message : BytesView) -> Bytes {
  @hmac.mac(key, message, sha256)
}

///|
/// Whether two byte strings are equal, without telling an attacker where they
/// first differ.
pub fn eq(a : BytesView, b : BytesView) -> Bool {
  @spec.eq(a, b)
}

///|
/// ChaCha20-Poly1305 under a key that must be exactly `key_size` bytes.
///
/// The key is taken as given rather than checked here: every caller derives it
/// from a hash, so a wrong length is a bug in this library and not a condition
/// to report.
pub fn seal(key : BytesView, nonce : BytesView, plain : BytesView) -> Bytes {
  let aead = @chachapoly.ChaChaPoly::new(key) catch {
    _ => abort("chachapoly: key or nonce of the wrong length")
  }
  aead.seal(nonce~, plain~, aad=b"")
}

///|
/// The same in reverse, or `None` if the tag does not match — which is the only
/// thing the caller needs to know about a failure here.
pub fn open(key : BytesView, nonce : BytesView, cipher : BytesView) -> Bytes? {
  let aead = @chachapoly.ChaChaPoly::new(key) catch {
    _ => abort("chachapoly: key or nonce of the wrong length")
  }
  return Some(aead.open(nonce~, cipher~, aad=b"") catch { _ => return None })
}

///|
/// The public key for a secret scalar, or `None` if the scalar is not a valid
/// X25519 input.
pub fn x25519_public(scalar : BytesView) -> Bytes? {
  return Some(@x25519.public(scalar) catch { _ => return None })
}

///|
/// The shared secret between a secret scalar and somebody's public key, or
/// `None` if the point is one of the low-order ones that would make the secret
/// predictable.
pub fn x25519_shared(scalar : BytesView, point : BytesView) -> Bytes? {
  return Some(@x25519.shared(scalar, point) catch { _ => return None })
}
