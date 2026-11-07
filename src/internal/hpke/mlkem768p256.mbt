// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// MLKEM768-P256 from draft-ietf-hpke-pq: an ML-KEM-768 encapsulation key and a
// P-256 point in one public key, and both secrets hashed into one rather than
// negotiated.
//
// It differs from X-Wing only in the curve it pairs with ML-KEM-768 and in the
// word the combiner hashes, which is why the two files look alike and must not
// be merged: a secret combined under one label is not a secret under the other.

///|
/// The word the combiner hashes after the two secrets and the two public values.
/// It is this KEM's, not this library's.
let hybrid_label : Bytes = b"MLKEM768-P256"

///|
/// The public key for a seed: the ML-KEM half and the P-256 point, in that
/// order.
pub fn hybrid_public_of(seed : BytesView) -> Bytes raise @spec.Refused {
  if seed.length() != seed_size {
    raise @spec.Refused::Key(want=seed_size, got=seed.length())
  }
  let material = hybrid_material(seed)
  let key = @mlkem.PrivateKey::from_seed(
    kind=@mlkem.K768,
    material.clamped_view(end=64),
  ) catch {
    _ =>
      raise @spec.Refused::Stanza(want="a seed ML-KEM-768 derives a key from")
  }
  let point = p256_public_of(material.clamped_view(start=64))
  key.encapsulation_key().bytes().add(point)
}

///|
/// Encapsulate to a public key, drawing the ML-KEM message and the P-256
/// ephemeral scalar from `random` in that order.
pub fn hybrid_encapsulate(
  public : BytesView,
  random : &@moonseed.Source,
) -> Encapsulated raise @spec.Refused {
  if public.length() != public_size(Mlkem768P256) {
    raise @spec.Refused::Key(
      want=public_size(Mlkem768P256),
      got=public.length(),
    )
  }
  let pq = @mlkem.PublicKey::new(
    kind=@mlkem.K768,
    public.clamped_view(end=1184),
  ) catch {
    _ => raise @spec.Refused::Stanza(want="an ML-KEM-768 encapsulation key")
  }
  let message = @spec.draw(random, 32)
  let sent = pq.encapsulate_with(message) catch {
    _ => raise @spec.Refused::Stanza(want="an ML-KEM-768 encapsulation key")
  }
  let scalar = p256_scalar(random)
  let share = p256_public_of(scalar)
  let theirs = public.clamped_view(start=1184)
  let dh = p256_shared(scalar, theirs)
  {
    enc: sent.ciphertext.add(share),
    shared: hybrid_combine(sent.secret, dh, share, theirs),
  }
}

///|
/// The secret behind an encapsulation, from the seed the identity was made of.
pub fn hybrid_decapsulate(
  seed : BytesView,
  enc : BytesView,
) -> Bytes raise @spec.Refused {
  if seed.length() != seed_size {
    raise @spec.Refused::Key(want=seed_size, got=seed.length())
  }
  if enc.length() != enc_size(Mlkem768P256) {
    raise @spec.Refused::Stanza(want="a 1153-byte MLKEM768-P256 encapsulation")
  }
  let material = hybrid_material(seed)
  let key = @mlkem.PrivateKey::from_seed(
    kind=@mlkem.K768,
    material.clamped_view(end=64),
  ) catch {
    _ =>
      raise @spec.Refused::Stanza(want="a seed ML-KEM-768 derives a key from")
  }
  let pq = key.decapsulate(enc.clamped_view(end=1088)) catch {
    _ => raise @spec.Refused::Stanza(want="an ML-KEM-768 ciphertext")
  }
  let share = enc.clamped_view(start=1088)
  let dh = p256_shared(material.clamped_view(start=64), share)
  let theirs = p256_public_of(material.clamped_view(start=64))
  hybrid_combine(pq, dh, share, theirs)
}

///|
/// A seed from a caller's bytes, by `DeriveKeyPair` of the one-stage KDF this
/// KEM defines.
pub fn hybrid_from_seed(seed : BytesView) -> Bytes {
  labeled_derive(Mlkem768P256, seed, "DeriveKeyPair", seed_size)
}

///|
/// The ninety-six bytes a seed expands into: the ML-KEM seed of FIPS 203 §7.1
/// first, then a P-256 scalar.
///
/// One SHAKE256 stream rather than two hashes, because that is how the KEM
/// defines the key, and a key that expands differently is a different key. A
/// candidate past the group order — which a hash produces once in two to the
/// thirty-second — costs another thirty-two bytes of the same stream.
fn hybrid_material(seed : BytesView) -> Bytes {
  let mut len = 64 + seed_size
  while true {
    let material = @sha3.shake256(seed, len)
    if is_scalar(material.clamped_view(start=64)) {
      return material
    }
    len = len + seed_size
  }
  abort("unreachable")
}

///|
/// The combiner: both secrets, both public values, and the label, hashed into
/// one thirty-two-byte secret.
fn hybrid_combine(
  pq : BytesView,
  dh : BytesView,
  share : BytesView,
  public : BytesView,
) -> Bytes {
  let parts = @buffer.Buffer(size_hint=64 + 64 + hybrid_label.length())
  parts.write_bytes(pq)
  parts.write_bytes(dh)
  parts.write_bytes(share)
  parts.write_bytes(public)
  parts.write_bytes(hybrid_label)
  @sha3.hash(parts.to_bytes(), kind=@sha3.Sha3_256)
}
