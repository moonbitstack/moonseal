// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// MLKEM768-X25519 (X-Wing): an ML-KEM-768 encapsulation key with an X25519
// public key behind it, combined into one secret with SHA3-256 rather than
// negotiated.
//
// This KEM is its own combiner — unlike the DHKEM of RFC 9180, it hands HPKE a
// secret directly — so what follows is the whole of it rather than a wrapper
// around an extraction.

///|
/// The string the combiner hashes after the two secrets and the two public
/// values. It is X-Wing's, not this library's, and it is what stops a secret
/// from one combination being read as a secret from another.
let xwing_label : Bytes = b"\\.//^\\"

///|
/// The public key for a seed: the ML-KEM half and the X25519 half, in that
/// order.
pub fn xwing_public_of(seed : BytesView) -> Bytes raise @spec.Refused {
  if seed.length() != seed_size {
    raise @spec.Refused::Key(want=seed_size, got=seed.length())
  }
  let material = @sha3.shake256(seed, 96)
  let key = @mlkem.PrivateKey::from_seed(
    kind=@mlkem.K768,
    material.clamped_view(end=64),
  ) catch {
    _ =>
      raise @spec.Refused::Stanza(want="a seed ML-KEM-768 derives a key from")
  }
  key.encapsulation_key().bytes().add(x_public(material.clamped_view(start=64)))
}

///|
/// Encapsulate to a public key, drawing the ML-KEM message and the X25519
/// ephemeral scalar from `random` in that order.
pub fn xwing_encapsulate(
  public : BytesView,
  random : &@moonseed.Source,
) -> Encapsulated raise @spec.Refused {
  if public.length() != public_size(XWing) {
    raise @spec.Refused::Key(want=public_size(XWing), got=public.length())
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
  let scalar = @spec.draw(random, 32)
  let share = x_public(scalar)
  let theirs = public.clamped_view(start=1184)
  let x_shared = shared_secret(scalar, theirs)
  let shared = combine(sent.secret, x_shared, share, theirs)
  { enc: sent.ciphertext.add(share), shared, }
}

///|
/// The secret behind an encapsulation, from the seed the identity was made of.
pub fn xwing_decapsulate(
  seed : BytesView,
  enc : BytesView,
) -> Bytes raise @spec.Refused {
  if seed.length() != seed_size {
    raise @spec.Refused::Key(want=seed_size, got=seed.length())
  }
  if enc.length() != enc_size(XWing) {
    raise @spec.Refused::Stanza(
      want="a 1120-byte MLKEM768-X25519 encapsulation",
    )
  }
  let material = @sha3.shake256(seed, 96)
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
  let x_shared = shared_secret(material.clamped_view(start=64), share)
  combine(pq, x_shared, share, x_public(material.clamped_view(start=64)))
}

///|
/// A seed from a caller's bytes, by `DeriveKeyPair` of the one-stage KDF this
/// KEM defines: SHAKE256 over the input, the suite, and the label.
pub fn xwing_from_seed(seed : BytesView) -> Bytes {
  labeled_derive(XWing, seed, "DeriveKeyPair", seed_size)
}

///|
/// The X25519 public key for a scalar. A freshly drawn one is always a key; the
/// clamping X25519 does is what makes that true.
fn x_public(scalar : BytesView) -> Bytes {
  @x25519.public(scalar) catch {
    _ => abort("xwing: a 32-byte scalar always has a public key")
  }
}

///|
/// The one combiner: both secrets, both public values, and the label, hashed
/// into one thirty-two-byte secret.
fn combine(
  pq : BytesView,
  x : BytesView,
  share : BytesView,
  public : BytesView,
) -> Bytes {
  let parts = @buffer.Buffer(size_hint=64 + 64 + xwing_label.length())
  parts.write_bytes(pq)
  parts.write_bytes(x)
  parts.write_bytes(share)
  parts.write_bytes(public)
  parts.write_bytes(xwing_label)
  @sha3.hash(parts.to_bytes(), kind=@sha3.Sha3_256)
}

///|
/// X25519 with the shared-secret rules of the scheme: an all-zero answer is a
/// low-order point and not a secret at all.
fn shared_secret(
  scalar : BytesView,
  point : BytesView,
) -> Bytes raise @spec.Refused {
  @x25519.shared(scalar, point) catch {
    _ =>
      raise @spec.Refused::Stanza(want="an X25519 share that is not low order")
  }
}
