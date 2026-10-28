// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
let alphabet : Bytes = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

///|
/// Not the base 64 it was supposed to be. `at` is the offset of the character
/// that gave it away, in characters from the start of the string.
pub(all) suberror Malformed {
  Malformed(at~ : Int32)
} derive(Eq, Debug)

///|
pub extend Malformed with Eq::{equal, not_equal}

///|
pub extend Malformed with Debug::{to_repr}

///|
/// The six bits a character stands for, or -1 if it stands for nothing. The
/// alphabet is checked by hand rather than by index so that a decoder rejects
/// `-` and `_`, which are the URL alphabet's and would otherwise silently
/// decode to the same bytes.
fn sextet(unit : UInt16) -> Int32 {
  if unit >= 65 && unit <= 90 {
    (unit - 65).to_int()
  } else if unit >= 97 && unit <= 122 {
    (unit - 97 + 26).to_int()
  } else if unit >= 48 && unit <= 57 {
    (unit - 48 + 52).to_int()
  } else if unit == 43 {
    62
  } else if unit == 47 {
    63
  } else {
    -1
  }
}

///|
/// Raw base 64: no padding, as RFC 4648 §3.5 wants it for anything that is not
/// armor.
pub fn encode(bytes : BytesView) -> String {
  encode_with(bytes, padding=false)
}

///|
/// Padded base 64, which only the ASCII armor asks for.
pub fn encode_padded(bytes : BytesView) -> String {
  encode_with(bytes, padding=true)
}

///|
fn encode_with(bytes : BytesView, padding~ : Bool) -> String {
  let n = bytes.length()
  let rest = n % 3
  let out = StringBuilder(size_hint=n / 3 * 4 + 4)
  let mut i = 0
  while i + 3 <= n {
    let value = (bytes[i].to_int() << 16) |
      (bytes[i + 1].to_int() << 8) |
      bytes[i + 2].to_int()
    out.write_char(alphabet[(value >> 18) & 0x3F].to_char())
    out.write_char(alphabet[(value >> 12) & 0x3F].to_char())
    out.write_char(alphabet[(value >> 6) & 0x3F].to_char())
    out.write_char(alphabet[value & 0x3F].to_char())
    i = i + 3
  }
  if rest == 1 {
    let value = bytes[i].to_int() << 16
    out.write_char(alphabet[(value >> 18) & 0x3F].to_char())
    out.write_char(alphabet[(value >> 12) & 0x3F].to_char())
    if padding {
      out.write_string("==")
    }
  } else if rest == 2 {
    let value = (bytes[i].to_int() << 16) | (bytes[i + 1].to_int() << 8)
    out.write_char(alphabet[(value >> 18) & 0x3F].to_char())
    out.write_char(alphabet[(value >> 12) & 0x3F].to_char())
    out.write_char(alphabet[(value >> 6) & 0x3F].to_char())
    if padding {
      out.write_char('=')
    }
  }
  out.to_string()
}

///|
/// Raw base 64 in, bytes out. Rejects padding, whitespace, everything outside
/// the alphabet, and the non-canonical encodings RFC 4648 §3.5 forbids: the
/// spare bits of a final group of two or three characters must be zero.
pub fn decode(text : StringView) -> Bytes raise Malformed {
  decode_with(text, padded=false)
}

///|
/// Padded base 64 in, bytes out. The length must be a multiple of four, at
/// most two `=` may follow the data, and the spare bits must be zero, so that
/// every byte string has exactly one spelled form.
pub fn decode_padded(text : StringView) -> Bytes raise Malformed {
  decode_with(text, padded=true)
}

///|
fn decode_with(text : StringView, padded~ : Bool) -> Bytes raise Malformed {
  let units = text.code_units()
  let total = units.length()
  let mut data = total
  if padded {
    if total % 4 != 0 {
      raise Malformed(at=total)
    }
    let mut pad = 0
    while data > 0 && units[data - 1] == 61 {
      data = data - 1
      pad = pad + 1
    }
    if pad > 2 || (data + pad) % 4 != 0 {
      raise Malformed(at=data)
    }
  } else {
    let mut i = 0
    while i < total {
      if units[i] == 61 {
        raise Malformed(at=i)
      }
      i = i + 1
    }
  }
  let rest = data % 4
  if rest == 1 {
    raise Malformed(at=data - 1)
  }
  let out = @buffer.Buffer(size_hint=data / 4 * 3 + 3)
  let mut i = 0
  while i + 4 <= data {
    let a = sextet(units[i])
    let b = sextet(units[i + 1])
    let c = sextet(units[i + 2])
    let d = sextet(units[i + 3])
    if a < 0 {
      raise Malformed(at=i)
    }
    if b < 0 {
      raise Malformed(at=i + 1)
    }
    if c < 0 {
      raise Malformed(at=i + 2)
    }
    if d < 0 {
      raise Malformed(at=i + 3)
    }
    out.write_byte(((a << 2) | (b >> 4)).to_byte())
    out.write_byte((((b & 0x0F) << 4) | (c >> 2)).to_byte())
    out.write_byte((((c & 0x03) << 6) | d).to_byte())
    i = i + 4
  }
  if rest == 2 {
    let a = sextet(units[i])
    let b = sextet(units[i + 1])
    if a < 0 {
      raise Malformed(at=i)
    }
    if b < 0 {
      raise Malformed(at=i + 1)
    }
    if (b & 0x0F) != 0 {
      raise Malformed(at=i + 1)
    }
    out.write_byte(((a << 2) | (b >> 4)).to_byte())
  } else if rest == 3 {
    let a = sextet(units[i])
    let b = sextet(units[i + 1])
    let c = sextet(units[i + 2])
    if a < 0 {
      raise Malformed(at=i)
    }
    if b < 0 {
      raise Malformed(at=i + 1)
    }
    if c < 0 {
      raise Malformed(at=i + 2)
    }
    if (c & 0x03) != 0 {
      raise Malformed(at=i + 2)
    }
    out.write_byte(((a << 2) | (b >> 4)).to_byte())
    out.write_byte((((b & 0x0F) << 4) | (c >> 2)).to_byte())
  }
  out.to_bytes()
}
