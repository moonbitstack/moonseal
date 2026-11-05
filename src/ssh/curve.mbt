// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// `p = 2^255 - 19`, the field both curves live in.
let prime : @bigint.BigInt = (1N << 255) - 19N

///|
/// The Edwards curve's `d`, as a field element: `-121665 / 121666`. It is what
/// the curve equation is written with, and it is computed rather than written
/// out because the literal is a number nobody can check by eye.
fn curve_d() -> @bigint.BigInt {
  let inverse = mod_inverse(121666N)
  (prime - 121665N * inverse % prime) % prime
}

///|
/// `value^(p-2) mod p`, which is its inverse for every value but zero, where it
/// is zero — the answer a caller here can live with, since a zero denominator
/// means a key of order one and X25519 refuses those on its own.
fn mod_inverse(value : @bigint.BigInt) -> @bigint.BigInt {
  value.pow(prime - 2N, modulus=prime)
}

///|
/// A little-endian byte string as a number. The curves write coordinates this
/// way and every other format writes numbers the other way, so the conversion is
/// here once.
fn from_le(bytes : BytesView) -> @bigint.BigInt {
  let reversed = Array::make(bytes.length(), b'\x00')
  for i in 0..<bytes.length() {
    reversed[bytes.length() - 1 - i] = bytes[i]
  }
  @bigint.BigInt::from_octets(Bytes::from_array(reversed))
}

///|
/// A number as thirty-two little-endian bytes, which is how a curve coordinate
/// is written.
fn to_le(value : @bigint.BigInt) -> Bytes {
  let big = value.to_octets(length=32)
  let out = Array::make(32, b'\x00')
  for i in 0..<32 {
    out[31 - i] = big[i]
  }
  Bytes::from_array(out)
}

///|
/// The X25519 public key behind an Ed25519 public key, by the birational map
/// `u = (1 + y) / (1 - y)`.
///
/// The signature that comes with the key is discarded: X25519 does not verify
/// anything, it only needs the point's u-coordinate, and the sign bit that
/// distinguishes two points with the same y is exactly what the map ignores.
///
/// A string that is not a point of the curve is refused, which is what keeps a
/// typo in a public key from becoming a file nobody can open.
fn montgomery(public : BytesView) -> Bytes raise @spec.Refused {
  if public.length() != 32 {
    raise @spec.Refused::Stanza(want="a 32-byte Ed25519 public key")
  }
  let raw = public.to_array()
  raw[31] = (raw[31].to_int() & 0x7f).to_byte()
  let y = from_le(Bytes::from_array(raw)[:])
  if y >= prime {
    raise @spec.Refused::Stanza(want="an Ed25519 public key below 2^255 - 19")
  }
  let y2 = y * y % prime
  let denominator = (curve_d() * y2 + 1N) % prime
  let x2 = (y2 - 1N + prime) % prime * mod_inverse(denominator) % prime
  let on_curve = x2.is_zero() || x2.pow((prime - 1N) / 2N, modulus=prime) == 1N
  if !on_curve {
    raise @spec.Refused::Stanza(want="a point of the Ed25519 curve")
  }
  let u = (1N + y) % prime * mod_inverse((prime + 1N - y) % prime) % prime
  to_le(u)
}
