// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// DHKEM(P-256, HKDF-SHA256) from RFC 9180 §7.1: an ECDH over the NIST prime,
// with the answer extracted and expanded under the KEM's own suite identifier.
//
// The extraction is what makes this a KEM rather than a raw exchange: a bare
// ECDH answer is a curve point's coordinate, and a coordinate is not uniformly
// distributed, so it is hashed before it is used as a key.

///|
/// The order of the P-256 group, big-endian. A scalar is a number in [1, n), and
/// this is what says whether thirty-two bytes are one.
let order : Bytes = b"\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xbc\xe6\xfa\xad\xa7\x17\x9e\x84\xf3\xb9\xca\xc2\xfc\x63\x25\x51"

///|
/// Whether thirty-two bytes are a scalar the group accepts: not zero, and below
/// its order.
///
/// The comparison is done on the bytes rather than through a big number because
/// big-endian bytes compare the way the numbers they spell do, and this runs
/// once per key rather than once per byte of anything.
fn is_scalar(candidate : BytesView) -> Bool {
  candidate.length() == seed_size &&
  !candidate.iter().all(fn(byte) { byte == b'\x00' }) &&
  below(candidate, order)
}

///|
/// The field's modulus, big-endian. A coordinate has to be below it, and a point
/// whose coordinate is not is a second spelling of a point rather than a point.
let modulus : Bytes = b"\xff\xff\xff\xff\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"

///|
/// The public point for a scalar, as the uncompressed SEC 1 point HPKE
/// serialises: `04` and the two coordinates.
pub fn p256_public_of(scalar : BytesView) -> Bytes raise @spec.Refused {
  @ecdh.public(scalar) catch {
    _ => raise @spec.Refused::Stanza(want="a P-256 scalar in [1, n)")
  }
}

///|
/// A scalar from a random source: thirty-two bytes, and a fresh draw in the
/// vanishingly unlikely case that they are not a scalar.
pub fn p256_scalar(random : &@moonseed.Source) -> Bytes raise @spec.Refused {
  @ecdh.generate(random) catch {
    why => raise @spec.Refused::Random(why)
  }
}

///|
/// Encapsulate to a public point: an ephemeral scalar, its point, and the secret
/// the two sides reach together.
pub fn p256_encapsulate(
  public : BytesView,
  random : &@moonseed.Source,
) -> Encapsulated raise @spec.Refused {
  if public.length() != public_size(P256) {
    raise @spec.Refused::Key(want=public_size(P256), got=public.length())
  }
  let scalar = p256_scalar(random)
  let enc = p256_public_of(scalar)
  let dh = p256_shared(scalar, public)
  { enc, shared: extract_and_expand(dh, enc.add(public.to_owned())), }
}

///|
/// The secret behind an encapsulation, from the scalar the identity holds.
pub fn p256_decapsulate(
  secret : BytesView,
  enc : BytesView,
) -> Bytes raise @spec.Refused {
  if secret.length() != seed_size {
    raise @spec.Refused::Key(want=seed_size, got=secret.length())
  }
  if enc.length() != enc_size(P256) {
    raise @spec.Refused::Stanza(want="a 65-byte P-256 encapsulation")
  }
  let dh = p256_shared(secret, enc)
  extract_and_expand(dh, enc.to_owned().add(p256_public_of(secret)))
}

///|
/// A scalar from a caller's seed, by `DeriveKeyPair` of RFC 9180 §7.1.3: a
/// candidate per counter, and the first one inside the group is the key.
pub fn p256_from_seed(seed : BytesView) -> Bytes raise @spec.Refused {
  let id = kem_suite(P256)
  let prk = extract(id, b""[:], "dkp_prk", seed)
  for counter in 0..<4 {
    let candidate = expand(
      id,
      prk,
      "candidate",
      Bytes::from_array([counter.to_byte()]),
      seed_size,
    )
    if is_scalar(candidate) {
      return candidate
    }
  }
  raise @spec.Refused::Stanza(want="a P-256 scalar derived from a seed")
}

///|
/// ECDH, with the peer's point checked against the curve: the check is what
/// keeps an invalid-curve attack from reading the scalar out a few bits at a
/// time.
fn p256_shared(
  scalar : BytesView,
  point : BytesView,
) -> Bytes raise @spec.Refused {
  @ecdh.shared(scalar, point) catch {
    _ => raise @spec.Refused::Stanza(want="a P-256 point on the curve")
  }
}

///|
/// The KEM's `ExtractAndExpand`: the shared secret, keyed with both points so
/// that neither side can be talked into a transcript the other did not see.
fn extract_and_expand(dh : BytesView, context : BytesView) -> Bytes {
  let id = kem_suite(P256)
  let prk = extract(id, b""[:], "eae_prk", dh)
  expand(id, prk, "shared_secret", context, 32)
}

///|
/// A point read from either SEC 1 form and given back uncompressed, which is the
/// form HPKE hashes into its key schedule and the form the curve's arithmetic
/// takes.
///
/// A coordinate at or past the modulus is refused rather than reduced: reducing
/// would accept a second spelling of the same point, and two spellings of one
/// recipient are two different tags.
pub fn p256_uncompressed(point : BytesView) -> Bytes raise @spec.Refused {
  guard canonical(point) else {
    raise @spec.Refused::Stanza(want="a P-256 point on the curve")
  }
  let key = @ecdsa.PublicKey::new(point) catch {
    _ => raise @spec.Refused::Stanza(want="a P-256 point on the curve")
  }
  key.bytes()
}

///|
/// Whether a point is written the way SEC 1 writes one and its coordinates are
/// inside the field.
///
/// Those are the two things the curve's arithmetic would otherwise accept a
/// second spelling of, and a second spelling of a recipient is a second tag.
fn canonical(point : BytesView) -> Bool {
  if point.length() == 33 {
    (point[0] == b'\x02' || point[0] == b'\x03') &&
    is_coordinate(point.clamped_view(start=1))
  } else if point.length() == public_size(P256) {
    point[0] == b'\x04' &&
    is_coordinate(point.clamped_view(start=1, end=33)) &&
    is_coordinate(point.clamped_view(start=33, end=65))
  } else {
    false
  }
}

///|
/// Whether thirty-two bytes are a coordinate the field accepts.
fn is_coordinate(value : BytesView) -> Bool {
  value.length() == seed_size && below(value, modulus)
}

///|
/// Whether thirty-two big-endian bytes spell a number below `limit`.
///
/// The comparison is done on the bytes because big-endian bytes compare the way
/// the numbers they spell do, and this runs once per key rather than once per
/// byte of anything.
fn below(value : BytesView, limit : BytesView) -> Bool {
  for i in 0..<seed_size {
    let mine = value[i].to_int()
    let bound = limit[i].to_int()
    if mine < bound {
      return true
    }
    if mine > bound {
      return false
    }
  }
  // Equal, which is not below.
  false
}
