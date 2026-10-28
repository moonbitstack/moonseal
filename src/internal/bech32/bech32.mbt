// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Which of the two checksums a string carries. `Bech32` is the original of
/// BIP 173, `Bech32m` the one of BIP 350 that differs only in a constant.
pub(all) enum Variant {
  Bech32
  Bech32m
} derive(Eq, Debug)

///|
pub extend Variant with Eq::{equal, not_equal}

///|
pub extend Variant with Debug::{to_repr}

///|
/// Not the bech32 it claims to be. `at` is the character offset, `want` says
/// what the encoding needed there.
pub(all) suberror Malformed {
  Malformed(at~ : Int32, want~ : String)
} derive(Eq, Debug)

///|
pub extend Malformed with Eq::{equal, not_equal}

///|
pub extend Malformed with Debug::{to_repr}

///|
/// The characters a data part may hold, in order of value.
let charset : Bytes = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l"

///|
/// The longest string either encoding allows, checksum and all.
pub let limit : Int32 = 90

///|
/// The five generator constants of the BCH code the checksum computes over.
let generators : Array[Int32] = [
  0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3,
]

///|
/// What a checksum over `values` comes to, before the variant's constant is
/// mixed in.
fn polymod(values : ArrayView[Int32]) -> Int32 {
  let mut check = 1
  for value in values {
    let top = check >> 25
    check = ((check & 0x1FFFFFF) << 5) ^ value
    for i in 0..<5 {
      if ((top >> i) & 1) == 1 {
        check = check ^ generators[i]
      }
    }
  }
  check
}

///|
/// The human-readable part, spread across the checksum as BIP 173 asks: the top
/// three bits of every character, a zero, then the bottom five.
fn expand(units : ArrayView[UInt16]) -> Array[Int32] {
  let out = Array(capacity=units.length() * 2 + 1)
  for unit in units {
    out.push((lowered(unit) >> 5).to_int())
  }
  out.push(0)
  for unit in units {
    out.push((lowered(unit) & 31).to_int())
  }
  out
}

///|
/// The checksum is always computed over the lowercase form, which is what makes
/// `A1G7SGD8` — a checksum taken over an uppercase part — invalid rather than
/// merely spelled differently.
fn lowered(unit : UInt16) -> UInt16 {
  if unit >= 65 && unit <= 90 {
    unit + 32
  } else {
    unit
  }
}

///|
/// The value a character stands for, or -1. Only the lowercase alphabet is
/// recognised; callers lowercase first.
fn value_of(unit : UInt16) -> Int32 {
  let lower = (if unit >= 65 && unit <= 90 { unit + 32 } else { unit }).to_int()
  let mut i = 0
  while i < charset.length() {
    if charset[i].to_int() == lower {
      return i
    }
    i = i + 1
  }
  -1
}

///|
/// The character for a value, in the case the output is being written in.
fn char_of(value : Int32, upper : Bool) -> Char {
  let unit = charset[value].to_int()
  (if upper && unit >= 97 && unit <= 122 { unit - 32 } else { unit }).unsafe_to_char()
}

///|
/// Eight bits at a time in, five at a time out, zero-padded as BIP 173 §2
/// describes.
fn to_words(bytes : BytesView) -> Array[Int32] {
  let out = Array(capacity=bytes.length() * 8 / 5 + 1)
  let mut acc = 0
  let mut bits = 0
  for byte in bytes {
    acc = (acc << 8) | byte.to_int()
    bits = bits + 8
    while bits >= 5 {
      bits = bits - 5
      out.push((acc >> bits) & 31)
    }
    acc = acc & ((1 << bits) - 1)
  }
  if bits > 0 {
    out.push((acc << (5 - bits)) & 31)
  }
  out
}

///|
/// Five bits at a time in, eight at a time out. The padding rule of BIP 173 §2
/// is enforced both ways: at most four spare bits, and all zero. Only callers
/// that mean a byte string may use it — the data part of an address is not one,
/// and its last five bits are free.
fn from_words(words : ArrayView[Int32], at~ : Int32) -> Bytes raise Malformed {
  let out = @buffer.Buffer(size_hint=words.length() * 5 / 8 + 1)
  let mut acc = 0
  let mut bits = 0
  for word in words {
    acc = (acc << 5) | word
    bits = bits + 5
    while bits >= 8 {
      bits = bits - 8
      out.write_byte(((acc >> bits) & 0xFF).to_byte())
    }
    acc = acc & ((1 << bits) - 1)
  }
  if bits >= 5 {
    raise Malformed(at~, want="no more than four bits of padding")
  }
  if acc != 0 {
    raise Malformed(at~, want="zero padding")
  }
  out.to_bytes()
}

///|
/// Five-bit words in, the string out. `hrp` is written as given, but the
/// checksum is always computed over its lowercase form, and a string is all one
/// case — so an uppercase `hrp` makes an uppercase string.
pub fn encode_words(
  hrp : StringView,
  words : ArrayView[Int32],
  variant~ : Variant,
) -> String raise Malformed {
  let hrp_units = hrp.code_units()
  let hrp_len = hrp_units.length()
  if hrp_len == 0 {
    raise Malformed(at=0, want="a human-readable part")
  }
  if hrp_len > 83 {
    raise Malformed(
      at=83,
      want="at most 83 characters in the human-readable part",
    )
  }
  let mut upper = false
  let mut lower = false
  for i, unit in hrp_units {
    if unit < 33 || unit > 126 {
      raise Malformed(at=i, want="printable ASCII in the human-readable part")
    }
    if unit >= 65 && unit <= 90 {
      upper = true
    }
    if unit >= 97 && unit <= 122 {
      lower = true
    }
  }
  if upper && lower {
    raise Malformed(at=0, want="one case throughout")
  }
  // One character for the separator, and six for the checksum.
  let total = hrp_len + 7 + words.length()
  if total > limit {
    raise Malformed(at=limit, want="at most 90 characters in the whole string")
  }
  let checksum_input = expand(hrp_units)
  for word in words {
    if word < 0 || word > 31 {
      raise Malformed(at=0, want="five-bit words")
    }
    checksum_input.push(word)
  }
  for _ in 0..<6 {
    checksum_input.push(0)
  }
  let constant = match variant {
    Bech32 => 1
    Bech32m => 0x2BC830A3
  }
  let residue = polymod(checksum_input) ^ constant
  let out = StringBuilder(size_hint=total)
  out.write_stringview(hrp)
  out.write_char('1')
  for word in words {
    out.write_char(char_of(word, upper))
  }
  for i in 0..<6 {
    out.write_char(char_of((residue >> (5 * (5 - i))) & 31, upper))
  }
  out.to_string()
}

///|
/// The string form of a byte string, which is what a key is.
pub fn encode(
  hrp : StringView,
  data : BytesView,
  variant~ : Variant,
) -> String raise Malformed {
  encode_words(hrp, to_words(data), variant~)
}

///|
/// A string back into the human-readable part as written and its data part as
/// five-bit words. Mixed case, a missing separator, a character outside the
/// alphabet and a wrong checksum are all refusals rather than best guesses.
pub fn decode(
  text : StringView,
) -> (String, Array[Int32], Variant) raise Malformed {
  let units = text.code_units()
  let length = units.length()
  if length > limit {
    raise Malformed(at=limit, want="at most 90 characters in the whole string")
  }
  if length == 0 {
    raise Malformed(at=0, want="a string")
  }
  let mut upper = false
  let mut lower = false
  for i, unit in units {
    if unit >= 65 && unit <= 90 {
      upper = true
    }
    if unit >= 97 && unit <= 122 {
      lower = true
    }
    if upper && lower {
      raise Malformed(at=i, want="one case throughout")
    }
  }
  let mut separator = -1
  for i, unit in units {
    if unit == 49 {
      separator = i
    }
  }
  if separator < 0 {
    raise Malformed(at=0, want="a separator")
  }
  if separator == 0 {
    raise Malformed(at=0, want="a human-readable part")
  }
  if separator > 83 {
    raise Malformed(
      at=83,
      want="at most 83 characters in the human-readable part",
    )
  }
  let mut i = 0
  while i < separator {
    if units[i] < 33 || units[i] > 126 {
      raise Malformed(at=i, want="printable ASCII in the human-readable part")
    }
    i = i + 1
  }
  if length - separator - 1 < 6 {
    raise Malformed(at=separator + 1, want="a checksum")
  }
  let words = Array(capacity=length - separator)
  i = separator + 1
  while i < length {
    let value = value_of(units[i])
    if value < 0 {
      raise Malformed(at=i, want="a character of the bech32 alphabet")
    }
    words.push(value)
    i = i + 1
  }
  let checksum_input = expand(units.clamped_view(end=separator))
  for word in words {
    checksum_input.push(word)
  }
  let residue = polymod(checksum_input)
  let variant = if residue == 1 {
    Bech32
  } else if residue == 0x2BC830A3 {
    Bech32m
  } else {
    raise Malformed(at=length - 6, want="a valid checksum")
  }
  let data = Array(capacity=words.length())
  i = 0
  while i < words.length() - 6 {
    data.push(words[i])
    i = i + 1
  }
  return (as_lower(units.clamped_view(end=separator)), data, variant)
}

///|
/// The same, for the case where the data part is a byte string.
pub fn decode_bytes(
  text : StringView,
) -> (String, Bytes, Variant) raise Malformed {
  let (hrp, words, variant) = decode(text)
  let at = hrp.length() + 1
  return (hrp, from_words(words, at~), variant)
}

///|
fn as_lower(units : ArrayView[UInt16]) -> String {
  let out = StringBuilder(size_hint=units.length())
  for unit in units {
    out.write_char(
      (if unit >= 65 && unit <= 90 { unit + 32 } else { unit }).unsafe_to_char(),
    )
  }
  out.to_string()
}
