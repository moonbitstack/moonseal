// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The four-byte tag a tagged recipient writes first in its stanza.
///
/// It is the first four bytes of an HKDF-Extract whose salt is the type's label
/// and whose input is the encapsulation followed by the first four bytes of the
/// SHA-256 of the recipient. The truncation is deliberate on both ends: the tag
/// is a hint for a reader that has to ask a hardware key for every decryption,
/// not a commitment, so it is short on purpose and colliding on it costs one
/// wasted attempt.
///
/// `recipient` is the part of the public key that names the device — the whole
/// compressed point for one type, and only the P-256 half for the hybrid, whose
/// ML-KEM key may not be readable without the device present.
pub fn compute(
  recipient : BytesView,
  enc : BytesView,
  label~ : BytesView,
) -> Bytes {
  let named = @buffer.Buffer(size_hint=enc.length() + 4)
  named.write_bytes(enc)
  named.write_bytes(@sha2.hash(recipient).clamped_view(end=4))
  let prk = @hkdf.extract(named.to_bytes(), sha256, salt=label)
  prk.bytes().clamped_view(end=4).to_owned()
}

///|
/// SHA-256, as the hash the tag truncates.
let sha256 : () -> &@cryptspec.Hash = fn() -> &@cryptspec.Hash {
  @sha2.Hasher::new()
}
