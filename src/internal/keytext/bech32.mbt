// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Which checksum: BIP 173's, or BIP 350's amendment. A key is always the first;
/// the second exists so that a caller who typed one can be told which mistake it
/// was instead of "not a key".
pub(all) enum Kind {
  Bech32
  Bech32m
}

///|
/// Why a string is not a key.
pub(all) suberror Malformed {
  /// Not bech32 at all.
  Bad
  /// A valid string of the other checksum kind: the case a caller can act on.
  OtherKind
  /// Bech32, but with a prefix other than the one the key type requires.
  Prefix
}

///|
/// The alphabet, in the order that gives a character its five-bit value.
let alphabet : String = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

///|
/// The final constant of each checksum family.
fn constant(kind : Kind) -> Int32 {
  match kind {
    Bech32 => 1
    Bech32m => 0x2bc8_30a3
  }
}

///|
/// The thirty-two-bit checksum function of BIP 173, over the prefix, the data
/// and the six checksum characters.
fn polymod(values : Array[Int32]) -> Int32 {
  let generator : Array[Int32] = [
    0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3,
  ]
  let mut checksum = 1
  for value in values {
    let top = checksum >> 25
    checksum = ((checksum & 0x1ff_ffff) << 5) ^ value
    for i in 0..<5 {
      if ((top >> i) & 1) == 1 {
        checksum = checksum ^ generator[i]
      }
    }
  }
  checksum
}

///|
/// The prefix as the checksum sees it: its high bits, a zero, then its low bits,
/// which is how a separator stays unambiguous.
fn expand(prefix : StringView) -> Array[Int32] {
  let out : Array[Int32] = []
  for i in 0..<prefix.length() {
    out.push(prefix[i].to_int() >> 5)
  }
  out.push(0)
  for i in 0..<prefix.length() {
    out.push(prefix[i].to_int() & 31)
  }
  out
}

///|
/// The five-bit value of a character, or `None` if it is outside the alphabet.
fn value_of(char : Char) -> Int32? {
  let code = char.to_int()
  for i in 0..<alphabet.length() {
    if alphabet[i].to_int() == code {
      return Some(i)
    }
  }
  None
}

///|
/// The character of a five-bit value, which is always in range here.
fn char_of(value : Int32) -> Char {
  alphabet[value].unsafe_to_char()
}

///|
/// Bytes as five-bit groups, with the last group padded with zeroes, which is
/// what the checksum covers.
fn words_of(bytes : BytesView) -> Array[Int32] {
  let out : Array[Int32] = []
  let mut held = 0
  let mut bits = 0
  for byte in bytes {
    held = (held << 8) | byte.to_int()
    bits = bits + 8
    while bits >= 5 {
      bits = bits - 5
      out.push((held >> bits) & 31)
    }
  }
  if bits > 0 {
    out.push((held << (5 - bits)) & 31)
  }
  out
}

///|
/// The other direction, and the padding rule: a group that does not fill a byte
/// must be zero, or two strings would name the same key.
fn bytes_of(words : Array[Int32]) -> Bytes? {
  let out : Array[Byte] = []
  let mut held = 0
  let mut bits = 0
  for word in words {
    held = (held << 5) | word
    bits = bits + 5
    if bits >= 8 {
      bits = bits - 8
      out.push(((held >> bits) & 0xff).to_byte())
    }
  }
  if bits >= 5 || (held & ((1 << bits) - 1)) != 0 {
    return None
  }
  Some(Bytes::from_array(out))
}

///|
/// A key's bytes, from its written form, which must carry `hrp`.
///
/// The letter case is the string's own business — bech32 allows either, never
/// both — and the checksum is always taken over the lowercase form, so the case
/// distinguishes a secret from a public key only by the prefix.
pub fn decode(
  text : StringView,
  hrp~ : String,
  kind~ : Kind,
) -> Bytes raise Malformed {
  let length = text.length()
  if length < 8 || length > 1 << 22 {
    raise Malformed::Bad
  }
  let mut lower = false
  let mut upper = false
  let mut separator = -1
  for i in 0..<length {
    let code = text[i].to_int()
    if code < 33 || code > 126 {
      raise Malformed::Bad
    }
    if code >= 97 && code <= 122 {
      lower = true
    } else if code >= 65 && code <= 90 {
      upper = true
    }
    if code == 49 {
      separator = i
    }
  }
  if lower && upper {
    raise Malformed::Bad
  }
  if separator < 1 || length - separator - 1 < 6 {
    raise Malformed::Bad
  }
  let prefix = StringBuilder(size_hint=separator)
  for i in 0..<separator {
    let code = text[i].to_int()
    prefix.write_char(
      if code >= 65 && code <= 90 {
        (code + 32).unsafe_to_char()
      } else {
        text[i].unsafe_to_char()
      },
    )
  }
  let prefix = prefix.to_string()
  let data : Array[Int32] = []
  for i in (separator + 1)..<length {
    let code = text[i].to_int()
    let char = if code >= 65 && code <= 90 {
      (code + 32).unsafe_to_char()
    } else {
      text[i].unsafe_to_char()
    }
    data.push(
      match value_of(char) {
        Some(value) => value
        None => raise Malformed::Bad
      },
    )
  }
  let checked = expand(prefix)
  for word in data {
    checked.push(word)
  }
  if polymod(checked) != constant(kind) {
    let other = match kind {
      Bech32 => Bech32m
      Bech32m => Bech32
    }
    if polymod(checked) == constant(other) {
      raise Malformed::OtherKind
    }
    raise Malformed::Bad
  }
  if prefix != hrp {
    raise Malformed::Prefix
  }
  // The last six groups are the checksum; what is left is the key.
  let body : Array[Int32] = []
  let body_length = data.length() - 6
  for i in 0..<body_length {
    body.push(data[i])
  }
  match bytes_of(body) {
    Some(bytes) => bytes
    None => raise Malformed::Bad
  }
}

///|
/// A key's written form.
pub fn encode(hrp : StringView, bytes : BytesView, kind~ : Kind) -> String {
  let words = words_of(bytes)
  let values = expand(hrp)
  for word in words {
    values.push(word)
  }
  for _ in 0..<6 {
    values.push(0)
  }
  let checksum = polymod(values) ^ constant(kind)
  let out = StringBuilder(size_hint=hrp.length() + words.length() + 8)
  out.write_string(hrp.to_owned())
  out.write_char('1')
  for word in words {
    out.write_char(char_of(word))
  }
  for i in 0..<6 {
    out.write_char(char_of((checksum >> (5 * (5 - i))) & 31))
  }
  out.to_string()
}
