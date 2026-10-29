// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The one version line this format has.
pub let version : String = "age-encryption.org/v1"

///|
/// How long a header this library will read before giving up.
///
/// The format has no ceiling, and that is a way to make a reader allocate until
/// it cannot: sixteen thousand stanzas of addressable text is one mebibyte, far
/// past any file addressed to real people.
pub let limit : Int32 = 1 << 20

///|
/// The MAC over a header, which is thirty-two bytes.
let mac_size : Int32 = 32

///|
/// A header in the shape it is written in: the stanzas, the MAC that came with
/// them, and the exact bytes the MAC covers.
///
/// The bytes are kept rather than recomputed because the MAC is defined over the
/// bytes on the wire. Re-rendering them would be right only for canonical input,
/// and being wrong about which input is canonical is how a file that parsed
/// yesterday stops opening today.
pub struct Header {
  priv stanzas : Array[@spec.Stanza]
  priv mac : Bytes
  priv prefix : Bytes
}

///|
/// A header with no MAC yet, as a sender has it.
pub fn Header::new(stanzas : Array[@spec.Stanza]) -> Self raise @spec.Refused {
  check(stanzas)
  let text = render(stanzas)
  let prefix = @buffer.from_bytes(text)
  prefix.write_bytes(b"---")
  { stanzas, mac: b"", prefix: prefix.to_bytes(), }
}

///|
/// The stanzas, in the order they are written.
pub fn Header::stanzas(self : Header) -> Array[@spec.Stanza] {
  self.stanzas
}

///|
/// The header as it appears in a file, MAC line and all, keyed from the file key.
pub fn Header::encode(self : Header, file_key~ : BytesView) -> Bytes {
  let out = @buffer.from_bytes(self.prefix)
  out.write_byte(b' ')
  out.write_bytes(
    @utf8.encode(@base64.encode(mac_over(self.prefix, file_key), padding=false)),
  )
  out.write_byte(b'\n')
  out.to_bytes()
}

///|
/// Check that the MAC this header carries is the one its bytes deserve. Called
/// before the payload is touched, because a header that does not verify is a
/// header somebody edited.
pub fn Header::verify(
  self : Header,
  file_key~ : BytesView,
) -> Unit raise @spec.Refused {
  if !@crypt.eq(self.mac, mac_over(self.prefix, file_key)) {
    raise @spec.Refused::Mac
  }
}

///|
/// Read a header from the front of `bytes`, and say how many bytes it took.
///
/// The count matters because the payload begins immediately after the MAC's line
/// feed with no separator: whoever reads a header has to know exactly where it
/// stopped.
pub fn Header::decode(bytes : BytesView) -> (Header, Int32) raise @spec.Refused {
  let length = bytes.length()
  let version_bytes = @utf8.encode(version)
  if length < version_bytes.length() + 1 {
    raise @spec.Refused::Header(at=0, want="the version line")
  }
  if !bytes.clamped_view(end=version_bytes.length()).equal(version_bytes[:]) {
    raise @spec.Refused::Header(at=0, want="the version line")
  }
  let mut at = version_bytes.length()
  if bytes[at].to_int() != 10 {
    raise @spec.Refused::Header(at~, want="the end of the version line")
  }
  at = at + 1
  let stanzas = Array(capacity=4)
  let mut mac = b""
  let mut prefix : BytesView = b""[:]
  while true {
    if at >= length {
      raise @spec.Refused::Header(at~, want="a recipient stanza and a MAC")
    }
    if starts_with(bytes, at, b"---") {
      // The MAC line, and with it the end of the header.
      let end = line_end(bytes, at)
      if end - at != 4 + 43 {
        raise @spec.Refused::Header(
          at~,
          want="--- followed by a space and 43 base64 characters",
        )
      }
      if bytes[at + 3].to_int() != 32 {
        raise @spec.Refused::Header(at=at + 3, want="a space after ---")
      }
      mac = @base64.decode(
        ascii(bytes, at + 4, end),
        padding=false,
        strict=true,
      ) catch {
        _ => raise @spec.Refused::Header(at=at + 4, want="the header MAC")
      }
      if mac.length() != mac_size {
        raise @spec.Refused::Header(at=at + 4, want="a 32-byte header MAC")
      }
      prefix = bytes.clamped_view(end=at + 3)
      at = end + 1
      break
    }
    if !starts_with(bytes, at, b"-> ") {
      raise @spec.Refused::Header(at~, want="a recipient stanza")
    }
    let (stanza, next) = stanza_at(bytes, at)
    stanzas.push(stanza)
    at = next
  }
  // The same rules a header is written under, applied on the way in: a file that
  // puts a passphrase beside a public key is not a file this format allows,
  // whoever wrote it.
  check(stanzas)
  return (({ stanzas, mac, prefix: prefix.to_owned(), } : Header), at)
}

///|
/// One stanza, from its `-> ` line to the end of its body.
fn stanza_at(
  bytes : BytesView,
  at : Int32,
) -> (@spec.Stanza, Int32) raise @spec.Refused {
  let end = line_end(bytes, at)
  let tokens = split_args(bytes.clamped_view(start=at, end~), at~)
  let kind = match tokens {
    [] => raise @spec.Refused::Header(at~, want="a recipient type")
    [kind, ..] => kind
  }
  // The first token is the type, which the stanza keeps apart from the rest so
  // that a recipient never has to remind itself which argument it is looking at.
  let args = Array(capacity=tokens.length())
  for i in 1..<tokens.length() {
    args.push(tokens[i])
  }
  let mut cursor = end + 1
  let body = @buffer.Buffer(size_hint=256)
  // Full lines are exactly 64 columns; the body ends at the first line that is
  // shorter, which may be empty.
  while true {
    let body_end = line_end(bytes, cursor)
    let width = body_end - cursor
    if width > 64 {
      raise @spec.Refused::Header(
        at=cursor,
        want="at most 64 base64 characters",
      )
    }
    let decoded = @base64.decode(
      ascii(bytes, cursor, body_end),
      padding=false,
      strict=true,
    ) catch {
      _ => raise @spec.Refused::Header(at=cursor, want="a base64 body")
    }
    body.write_bytes(decoded)
    cursor = body_end + 1
    if width < 64 {
      break
    }
  }
  return (@spec.Stanza::new(kind~, args~, body=body.to_bytes()), cursor)
}

///|
/// The arguments of a stanza line, and the offset of the stanza for the errors.
/// One space between them, no space at either end, and nothing outside the
/// printable range: the line is a token list, not free text.
fn split_args(
  line : BytesView,
  at~ : Int32,
) -> Array[String] raise @spec.Refused {
  let args = Array(capacity=4)
  let length = line.length()
  let mut start = 3
  let mut i = 3
  while i <= length {
    if i == length || line[i].to_int() == 32 {
      if i == start {
        raise @spec.Refused::Header(at=at + start, want="an argument")
      }
      args.push(argument(line, start, i, at~))
      start = i + 1
    } else if line[i].to_int() < 33 || line[i].to_int() > 126 {
      raise @spec.Refused::Header(
        at=at + i,
        want="printable ASCII in an argument",
      )
    }
    i = i + 1
  }
  args
}

///|
/// A run of printable ASCII as a string, which is what an argument and a type
/// are.
fn argument(
  line : BytesView,
  start : Int32,
  end : Int32,
  at~ : Int32,
) -> String raise @spec.Refused {
  let mut i = start
  while i < end {
    let unit = line[i].to_int()
    if unit < 33 || unit > 126 {
      raise @spec.Refused::Header(at=at + i, want="printable ASCII")
    }
    i = i + 1
  }
  ascii(line, start, end)
}

///|
/// Bytes that are about to be handed to a decoder, as text. The character range
/// is the decoder's business.
fn ascii(bytes : BytesView, start : Int32, end : Int32) -> String {
  let out = StringBuilder(size_hint=end - start)
  for i in start..<end {
    out.write_char(bytes[i].to_int().unsafe_to_char())
  }
  out.to_string()
}

///|
/// Where the line starting at `at` ends, which is where the next `\n` is.
fn line_end(bytes : BytesView, at : Int32) -> Int32 raise @spec.Refused {
  let mut i = at
  while i < bytes.length() {
    if bytes[i].to_int() == 10 {
      return i
    }
    i = i + 1
  }
  raise @spec.Refused::Header(at~, want="the end of a line")
}

///|
fn starts_with(bytes : BytesView, at : Int32, prefix : BytesView) -> Bool {
  if at + prefix.length() > bytes.length() {
    return false
  }
  bytes.clamped_view(start=at, end=at + prefix.length()).equal(prefix)
}

///|
/// The checks a header has to pass before it is written: at least one stanza,
/// and any scrypt stanza alone.
///
/// The second is the format's, not this library's: a password-derived key
/// carries no authentication of its own, so mixing one with a public-key stanza
/// would let whoever holds the password be told a weaker story about who else
/// can read the file.
fn check(stanzas : Array[@spec.Stanza]) -> Unit raise @spec.Refused {
  if stanzas.length() == 0 {
    raise @spec.Refused::Header(at=0, want="at least one recipient stanza")
  }
  let mut scrypt = 0
  for stanza in stanzas {
    if stanza.kind == "scrypt" {
      scrypt = scrypt + 1
    }
    if stanza.kind == "" {
      raise @spec.Refused::Header(at=0, want="a recipient type")
    }
    for arg in stanza.args {
      if arg == "" {
        raise @spec.Refused::Header(at=0, want="an argument")
      }
    }
  }
  if scrypt > 0 && stanzas.length() > 1 {
    raise @spec.Refused::Header(at=0, want="a scrypt stanza on its own")
  }
}

///|
/// The header as text, up to but not including the `---` of the MAC line.
fn render(stanzas : Array[@spec.Stanza]) -> Bytes {
  let out = @buffer.Buffer(size_hint=1024)
  out.write_bytes(@utf8.encode(version))
  out.write_byte(b'\n')
  for stanza in stanzas {
    out.write_bytes(b"-> ")
    out.write_bytes(@utf8.encode(stanza.kind))
    for arg in stanza.args {
      out.write_byte(b' ')
      out.write_bytes(@utf8.encode(arg))
    }
    out.write_byte(b'\n')
    let body = @base64.encode(stanza.body, padding=false)
    let mut at = 0
    while at < body.length() {
      let end = if at + 64 < body.length() { at + 64 } else { body.length() }
      out.write_bytes(@utf8.encode(body.exact_view(start=at, end~)))
      out.write_byte(b'\n')
      at = end
    }
    // A body whose base64 is a multiple of 64 columns still needs a line
    // shorter than 64 to close it.
    if body.length() % 64 == 0 {
      out.write_byte(b'\n')
    }
  }
  out.to_bytes()
}

///|
/// HMAC-SHA-256 over the header's bytes, keyed from the file key.
fn mac_over(prefix : BytesView, file_key : BytesView) -> Bytes {
  let key = @crypt.hkdf(file_key, b"", b"header", len=32)
  @crypt.hmac(key, prefix)
}
