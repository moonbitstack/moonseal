// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The label between the dashes, which is also the name this format is known by
/// to anything that reads PEM blocks.
pub let label : String = "AGE ENCRYPTED FILE"

///|
/// How many columns a line of the body holds, and how many bytes that is.
let columns : Int32 = 64

///|
let group : Int32 = 48

///|
/// The line that starts a block, and the one that ends it.
fn begin_line() -> Bytes {
  let out = @buffer.Buffer(size_hint=40)
  out.write_bytes(b"-----BEGIN ")
  out.write_bytes(@utf8.encode(label))
  out.write_bytes(b"-----")
  out.to_bytes()
}

///|
fn end_line() -> Bytes {
  let out = @buffer.Buffer(size_hint=40)
  out.write_bytes(b"-----END ")
  out.write_bytes(@utf8.encode(label))
  out.write_bytes(b"-----")
  out.to_bytes()
}

///|
/// A block around `bytes`, as text. Every line ends in a line feed, including
/// the last one, so that the result survives being concatenated.
pub fn encode(bytes : BytesView) -> String {
  let encoder = Encoder::new()
  let text = StringBuilder(size_hint=bytes.length() * 3 / 2 + 96)
  text.write_string(head())
  text.write_string(encoder.write(bytes))
  text.write_string(encoder.finish())
  text.to_string()
}

///|
/// The line that opens a block, with its line feed.
pub fn head() -> String {
  let out = StringBuilder(size_hint=40)
  out.write_string("-----BEGIN \{label}-----\n")
  out.to_string()
}

///|
/// A block back into bytes, or a refusal. See the package comment for what is
/// allowed around the block and what is not.
pub fn decode(text : StringView) -> Bytes raise @spec.Refused {
  let decoder = Decoder::new()
  decoder.push(text)
  decoder.finish()
}

///|
/// A block written a piece at a time, so that a file larger than memory can be
/// armored.
pub struct Encoder {
  priv pending : @buffer.Buffer
}

///|
pub fn Encoder::new() -> Self {
  { pending: @buffer.Buffer(size_hint=group), }
}

///|
/// Take some bytes and give back the lines that are now complete. Nothing comes
/// back until at least 48 bytes have arrived, which is exactly one line.
pub fn Encoder::write(self : Encoder, bytes : BytesView) -> String {
  self.pending.write_bytes(bytes)
  let held = self.pending.to_bytes()
  let out = StringBuilder(size_hint=held.length() * 3 / 2 + 4)
  let mut at = 0
  while held.length() - at >= group {
    out.write_string(
      @base64.encode(held.clamped_view(start=at, end=at + group), padding=false),
    )
    out.write_char('\n')
    at = at + group
  }
  self.pending.reset()
  self.pending.write_bytes(held.clamped_view(start=at))
  out.to_string()
}

///|
/// The rest of the block: the last, shorter line if there is one, and the line
/// that ends it. An empty input writes no body line at all, which is a block
/// that carries no bytes rather than a block that carries an empty line.
pub fn Encoder::finish(self : Encoder) -> String {
  let held = self.pending.to_bytes()
  let out = StringBuilder(size_hint=8)
  if held.length() > 0 {
    out.write_string(@base64.encode(held))
    out.write_char('\n')
  }
  out.write_string("-----END \{label}-----\n")
  out.to_string()
}

///|
/// Where a decoder is in the block.
enum Place {
  Leading
  Body
  AfterShortLine
  Done
}

///|
/// A block read a piece at a time.
pub struct Decoder {
  priv mut place : Place
  priv line : @buffer.Buffer
  priv out : @buffer.Buffer
  priv mut at : Int32
}

///|
pub fn Decoder::new() -> Self {
  {
    place: Leading,
    line: @buffer.Buffer(size_hint=columns + 2),
    out: @buffer.Buffer(size_hint=1024),
    at: 0,
  }
}

///|
/// Feed text. Complete lines are decoded as they arrive; what has been decoded so
/// far is available from `take`.
pub fn Decoder::push(
  self : Decoder,
  text : StringView,
) -> Unit raise @spec.Refused {
  for unit in text.code_units() {
    if unit > 127 {
      raise @spec.Refused::Armor(at=self.at, want="printable ASCII")
    }
    let code = unit.to_int()
    if code == 10 {
      self.line_of()
    } else {
      if self.line.length() >= columns + 2 {
        raise @spec.Refused::Armor(
          at=self.at,
          want="a line of at most 64 characters",
        )
      }
      self.line.write_byte(code.to_byte())
    }
    self.at = self.at + 1
  }
}

///|
/// What has been decoded so far, and clear it.
pub fn Decoder::take(self : Decoder) -> Bytes {
  let bytes = self.out.to_bytes()
  self.out.reset()
  bytes
}

///|
/// The end of the text: whatever was left of a last line without its line feed,
/// and a check that the block was closed.
pub fn Decoder::finish(self : Decoder) -> Bytes raise @spec.Refused {
  if self.line.length() > 0 {
    self.line_of()
  }
  match self.place {
    Done => ()
    _ =>
      raise @spec.Refused::Armor(at=self.at, want="the end of the armored file")
  }
  self.take()
}

///|
/// One line, which is everything the state machine ever looks at.
fn Decoder::line_of(self : Decoder) -> Unit raise @spec.Refused {
  // A carriage return belongs to the line ending, not to the line.
  let raw = self.line.to_bytes()
  let width = if raw.length() > 0 && raw[raw.length() - 1].to_int() == 13 {
    raw.length() - 1
  } else {
    raw.length()
  }
  let line = raw.clamped_view(end=width)
  let start = self.at - width
  self.line.reset()
  match self.place {
    Leading =>
      if line.equal(begin_line()[:]) {
        self.place = Body
      } else if !blank(line) {
        raise @spec.Refused::Armor(
          at=start,
          want="the start of the armored file",
        )
      }
    Body =>
      if line.equal(end_line()[:]) {
        self.place = Done
      } else if width == 0 {
        raise @spec.Refused::Armor(at=start, want="a line of base64")
      } else if width > columns {
        raise @spec.Refused::Armor(
          at=start,
          want="a line of at most 64 characters",
        )
      } else {
        let decoded = @base64.decode(text_of(line), padding=true, strict=true) catch {
          _ => raise @spec.Refused::Armor(at=start, want="canonical base64")
        }
        self.out.write_bytes(decoded)
        if width < columns {
          self.place = AfterShortLine
        }
      }
    AfterShortLine =>
      if line.equal(end_line()[:]) {
        self.place = Done
      } else {
        raise @spec.Refused::Armor(at=start, want="the end of the armored file")
      }
    Done =>
      if !blank(line) {
        raise @spec.Refused::Armor(
          at=start,
          want="nothing after the armored file",
        )
      }
  }
}

///|
/// Whether a line is nothing but whitespace, which is all that may surround a
/// block.
fn blank(line : BytesView) -> Bool {
  for byte in line {
    let unit = byte.to_int()
    if unit != 32 && unit != 9 && unit != 13 && unit != 11 && unit != 12 {
      return false
    }
  }
  true
}

///|
fn text_of(line : BytesView) -> String {
  let out = StringBuilder(size_hint=line.length())
  for byte in line {
    out.write_char(byte.to_int().unsafe_to_char())
  }
  out.to_string()
}
