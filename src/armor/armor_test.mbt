// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The same bytes, armored and back, at every length where the base64 padding or
/// the last line changes shape.
test "an armored file round trips" {
  for len in [0, 1, 2, 3, 47, 48, 49, 72, 1000, 4096] {
    let plain = Bytes::make(len, 0x7E)
    let text = @armor.encode(plain)
    assert_eq(@armor.decode(text), plain, msg="at \{len} bytes")
  }
}

///|
/// A block is sixty-four columns wide except for its last line, and that last line
/// carries the padding — the one place in this format that uses any.
test "an armored block is sixty-four columns" {
  let text = @armor.encode(Bytes::make(100, 0))
  let lines = text.split("\n").collect()
  assert_eq(lines[0], "-----BEGIN AGE ENCRYPTED FILE-----")
  assert_eq(lines[1].length(), 64)
  assert_eq(lines[2].length(), 64)
  // 100 bytes are 136 base64 characters: two full lines and one of eight, padded.
  assert_eq(lines[3].length(), 8)
  assert_true(lines[3].has_suffix("="))
  assert_eq(lines[4], "-----END AGE ENCRYPTED FILE-----")
  assert_eq(lines[5], "")
}

///|
/// A body whose base64 is a multiple of sixty-four columns does not need a shorter
/// line to close it: unlike the header, this grammar counts lines, not a terminator.
test "a last line may be a full line" {
  let text = @armor.encode(Bytes::make(48, 0x11))
  let lines = text.split("\n").collect()
  assert_eq(lines.length(), 4)
  assert_eq(lines[1].length(), 64)
  assert_eq(lines[2], "-----END AGE ENCRYPTED FILE-----")
  assert_eq(@armor.decode(text), Bytes::make(48, 0x11))
}

///|
/// The piece-at-a-time encoder has to produce exactly what the one-shot encoder
/// does, or a file armored by a stream would not decode anywhere else.
test "armor written in pieces is the same armor" {
  let plain = Bytes::make(1000, 0x31)
  let encoder = @armor.Encoder::new()
  let pieces = StringBuilder(size_hint=2048)
  pieces.write_string(@armor.head())
  let mut at = 0
  while at < plain.length() {
    let end = if at + 7 < plain.length() { at + 7 } else { plain.length() }
    pieces.write_string(encoder.write(plain.clamped_view(start=at, end~)))
    at = end
  }
  pieces.write_string(encoder.finish())
  assert_eq(pieces.to_string(), @armor.encode(plain))
}

///|
/// And the decoder takes the text in whatever pieces it arrives in.
test "armor read in pieces is the same file" {
  let plain = Bytes::make(300, 0x32)
  let text = @armor.encode(plain)
  let decoder = @armor.Decoder::new()
  let out = @buffer.Buffer(size_hint=512)
  let units = text.code_units()
  let mut at = 0
  // Seven characters at a time cuts inside lines as well as between them, which
  // is the point.
  while at < units.length() {
    let end = if at + 7 < units.length() { at + 7 } else { units.length() }
    decoder.push(text_of(units, at, end))
    out.write_bytes(decoder.take())
    at = end
  }
  out.write_bytes(decoder.finish())
  assert_eq(out.to_bytes(), plain)
}

///|
fn text_of(units : ArrayView[UInt16], start : Int32, end : Int32) -> StringView {
  let out = StringBuilder(size_hint=end - start)
  for i in start..<end {
    out.write_char(units[i].unsafe_to_char())
  }
  out.to_string()
}

///|
/// Whitespace around a block is a mail client, not a different file.
test "armor allows whitespace around it and line endings of either kind" {
  let text = @armor.encode(b"the quick brown fox")
  assert_eq(
    @armor.decode("\n  \r\n\t\n" + text + "\r\n \n"),
    b"the quick brown fox",
  )
  let crlf = text.replace_all(old="\n", new="\r\n")
  assert_eq(@armor.decode(crlf), b"the quick brown fox")
  // The last line feed may be missing altogether.
  assert_eq(
    @armor.decode(crlf.rev_before("\r\n").unwrap_or("")),
    b"the quick brown fox",
  )
}

///|
/// The refusals, one per way of writing bytes that are nearly the same bytes.
test "armor refuses what is not armor" {
  let text = @armor.encode(b"the quick brown fox")
  let lines = text.split("\n").collect()
  let body = lines[1].to_owned()
  let unpadded = body.rev_before("=").unwrap_or("").to_owned()
  let until_end = text.rev_before("-----END").unwrap_or("").to_owned()
  let cases = [
    ("lowercase markers", text.replace_all(old="BEGIN", new="begin")),
    ("no end line", until_end),
    ("something before the block", "garbage\n" + text),
    ("something after the block", text + "garbage\n"),
    (
      "an empty line in the body",
      "-----BEGIN AGE ENCRYPTED FILE-----\n" +
      body +
      "\n\n-----END AGE ENCRYPTED FILE-----\n",
    ),
    (
      "a space at the end of a body line",
      "-----BEGIN AGE ENCRYPTED FILE-----\n" +
      body +
      " \n-----END AGE ENCRYPTED FILE-----\n",
    ),
    (
      "a body line that is too long",
      "-----BEGIN AGE ENCRYPTED FILE-----\n" +
      body +
      body +
      "\n-----END AGE ENCRYPTED FILE-----\n",
    ),
    (
      "base 64 without its padding",
      "-----BEGIN AGE ENCRYPTED FILE-----\n" +
      unpadded +
      "\n-----END AGE ENCRYPTED FILE-----\n",
    ),
    (
      "the wrong label",
      text.replace_all(old="AGE ENCRYPTED FILE", new="PGP MESSAGE"),
    ),
    ("no block at all", "just some text\n"),
  ]
  for case in cases {
    let refused = try {
      ignore(@armor.decode(case.1))
      false
    } catch {
      @spec.Refused::Armor(..) => true
      _ => false
    }
    assert_true(refused, msg="accepted: " + case.0)
  }
}

///|
test "an empty block carries no bytes" {
  let text = @armor.encode(b"")
  assert_eq(
    text, "-----BEGIN AGE ENCRYPTED FILE-----\n-----END AGE ENCRYPTED FILE-----\n",
  )
  assert_eq(@armor.decode(text), b"")
}
