// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A cursor over SSH's wire encoding (RFC 4251 §5): a sequence of strings, each
/// with its length in front of it, and numbers written with the same prefix.
///
/// Every read either consumes what it says it consumed or raises; there is no
/// way to ask for a length that is not there and get a short answer instead.
priv struct Wire {
  raw : Bytes
  mut at : Int32
}

///|
fn Wire::new(bytes : BytesView) -> Self {
  { raw: bytes.to_owned(), at: 0, }
}

///|
/// How much is left, which is how a parser knows the last field has been read.
fn Wire::left(self : Wire) -> Int32 {
  self.raw.length() - self.at
}

///|
fn Wire::uint32(self : Wire) -> Int32 raise @spec.Refused {
  if self.left() < 4 {
    raise @spec.Refused::Stanza(want="four bytes of a length")
  }
  let mut value = 0
  for i in 0..<4 {
    value = (value << 8) | self.raw[self.at + i].to_int()
  }
  self.at = self.at + 4
  value
}

///|
fn Wire::string(self : Wire) -> Bytes raise @spec.Refused {
  let length = self.uint32()
  if length < 0 || length > self.left() {
    raise @spec.Refused::Stanza(want="a string that fits in the key")
  }
  let piece = self.raw
    .clamped_view(start=self.at, end=self.at + length)
    .to_owned()
  self.at = self.at + length
  piece
}

///|
fn Wire::text(self : Wire) -> String raise @spec.Refused {
  ascii(self.string())
}

///|
/// A multiple-precision integer (RFC 4251 §5): two's complement, big-endian,
/// with as few bytes as it takes.
///
/// A key holds only positive numbers, so a leading `0x00` is the sign byte and
/// nothing else, and a leading `0x01` bit set without one is a negative number
/// this library will not read.
fn Wire::mpint(self : Wire) -> Bytes raise @spec.Refused {
  let raw = self.string()
  // The sign is the first byte of what was written, before the zero a positive
  // number with its top bit set has to carry: strip first and the number reads
  // as negative whenever its most significant byte is above 0x7f.
  if raw.length() > 0 && (raw[0].to_int() & 0x80) != 0 {
    raise @spec.Refused::Stanza(want="a positive number in an SSH key")
  }
  let mut start = 0
  while start < raw.length() && raw[start] == (0 : Byte) {
    start = start + 1
  }
  raw.clamped_view(start~).to_owned()
}

///|
/// A string written the way SSH writes one: four bytes of length, then the
/// bytes.
fn put_string(out : @buffer.Buffer, bytes : BytesView) -> Unit {
  put_uint32(out, bytes.length())
  out.write_bytes(bytes)
}

///|
fn put_uint32(out : @buffer.Buffer, value : Int32) -> Unit {
  for shift in [24, 16, 8, 0] {
    out.write_byte(((value >> shift) & 0xff).to_byte())
  }
}

///|
/// A positive number as an mpint: no leading zeroes, and one added when the top
/// bit would otherwise read as a sign.
fn put_mpint(out : @buffer.Buffer, bytes : BytesView) -> Unit {
  let mut start = 0
  while start < bytes.length() && bytes[start] == (0 : Byte) {
    start = start + 1
  }
  let value = bytes.clamped_view(start~)
  if value.length() > 0 && (value[0].to_int() & 0x80) != 0 {
    put_string(out, b"\x00".add(value.to_owned()))
  } else {
    put_string(out, value)
  }
}

///|
/// The number of significant bits in a big-endian positive integer.
fn bits(bytes : BytesView) -> Int32 {
  let mut start = 0
  while start < bytes.length() && bytes[start] == (0 : Byte) {
    start = start + 1
  }
  if start == bytes.length() {
    return 0
  }
  let first = bytes[start].to_int()
  let mut top = 7
  while ((first >> top) & 1) == 0 {
    top = top - 1
  }
  (bytes.length() - start) * 8 - (7 - top)
}

///|
/// The four bytes that name a key: the start of the SHA-256 of the public key as
/// SSH writes it, in base64.
///
/// It is a hint a stanza carries so a reader can skip the ones that are not
/// worth trying; it is not an identity, and two keys may share one.
fn tag_of(blob : BytesView) -> String {
  @base64.encode(@sha2.hash(blob).clamped_view(end=4), padding=false)
}

///|
/// The words of an `authorized_keys` line: options, then the type, then the key,
/// then whatever comment the owner left.
///
/// Options can contain spaces inside quotes, so the scan looks for a token that
/// names a key type rather than assuming the first one is it — which is also
/// what makes a `known_hosts` line, with a host in front, parse.
fn words_of(text : StringView) -> Array[String] {
  let words = Array(capacity=4)
  let word = @buffer.Buffer(size_hint=32)
  for unit in text.code_units() {
    let code = unit.to_int()
    if code == 32 || code == 9 || code == 10 || code == 13 {
      if word.length() > 0 {
        words.push(ascii(word.to_bytes()))
        word.reset()
      }
    } else {
      word.write_byte(code.to_byte())
    }
  }
  if word.length() > 0 {
    words.push(ascii(word.to_bytes()))
  }
  words
}

///|
/// Bytes as text, one byte per character. A key line is ASCII by definition; a
/// byte outside it becomes a replacement character, which matches no key type
/// and so fails where it should.
fn ascii(bytes : BytesView) -> String {
  let out = StringBuilder(size_hint=bytes.length())
  for byte in bytes {
    let unit = byte.to_int()
    out.write_char(if unit < 0x80 { unit.unsafe_to_char() } else { '\u{FFFD}' })
  }
  out.to_string()
}
