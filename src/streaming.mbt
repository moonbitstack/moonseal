// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The same file, written a piece at a time: nothing larger than one chunk is
/// ever held, which is what makes a file bigger than memory something this
/// library can seal.
pub fn seal_stream(
  sink : &Sink,
  recipients : Array[&@spec.Recipient],
  source : &Source,
  entropy~ : @spec.Entropy,
) -> Unit raise @spec.Refused {
  let file_key = entropy.take(len=file_key_size)
  let stanzas = Array(capacity=recipients.length())
  for recipient in recipients {
    stanzas.push(recipient.wrap(file_key~, entropy~))
  }
  let head = @header.Header::new(stanzas)
  sink.write(bytes=head.encode(file_key~))
  let nonce = entropy.take(len=@stream.nonce)
  sink.write(bytes=nonce)
  let sealer = @stream.Sealer::new(key=@stream.payload_key(file_key~, nonce~))
  let reader = Reader::new(source)
  while true {
    // One byte of lookahead is what tells the last chunk from the others: the
    // format marks it, so it has to be known before it is sealed.
    reader.fill(want=@stream.chunk + 1)
    let held = reader.available()
    if held == 0 {
      sink.write(bytes=sealer.chunk(plain=b""[:], last=true))
      break
    }
    if held <= @stream.chunk {
      sink.write(bytes=sealer.chunk(plain=reader.take(len=held), last=true))
      break
    }
    sink.write(
      bytes=sealer.chunk(plain=reader.take(len=@stream.chunk), last=false),
    )
  }
}

///|
/// Seal to a sink, as an armored text block. The text is written in the same
/// pieces the file is, so the whole of it never exists at once either.
pub fn seal_stream_armored(
  sink : &Sink,
  recipients : Array[&@spec.Recipient],
  source : &Source,
  entropy~ : @spec.Entropy,
) -> Unit raise @spec.Refused {
  let armor = ArmoredSink::new(sink)
  seal_stream(armor, recipients, source, entropy~)
  armor.finish()
}

///|
/// Open a file from a source, writing the plaintext to a sink as it is
/// authenticated. Nothing is written until the header has verified.
pub fn open_stream(
  sink : &Sink,
  identities : Array[&@spec.Identity],
  source : &Source,
) -> Unit raise @spec.Refused {
  let reader = Reader::new(source)
  let text = read_header(reader)
  let (head, _) = @header.Header::decode(text)
  let file_key = file_key_of(identities, head)
  reader.fill(want=@stream.nonce)
  if reader.available() < @stream.nonce {
    raise @spec.Refused::Header(
      at=reader.available(),
      want="a 16-byte payload nonce",
    )
  }
  let nonce = reader.take(len=@stream.nonce)
  let opener = @stream.Opener::new(key=@stream.payload_key(file_key~, nonce~))
  let mut base = 0
  while true {
    reader.fill(want=@stream.chunk + @stream.tag + 1)
    let held = reader.available()
    if held == 0 {
      raise @spec.Refused::Payload(at=@stream.nonce + base)
    }
    let last = held <= @stream.chunk + @stream.tag
    let take = if last { held } else { @stream.chunk + @stream.tag }
    let plain = opener.chunk(cipher=reader.view().clamped_view(end=take), last~) catch {
      @spec.Refused::Payload(at~) =>
        raise @spec.Refused::Payload(at=@stream.nonce + base + at)
      error => raise error
    }
    sink.write(bytes=plain)
    ignore(reader.take(len=take))
    base = base + take
    if last {
      break
    }
  }
}

///|
/// Open an armored text block from a source.
pub fn open_stream_armored(
  sink : &Sink,
  identities : Array[&@spec.Identity],
  source : &Source,
) -> Unit raise @spec.Refused {
  open_stream(sink, identities, ArmoredSource::new(source))
}

///|
/// A source over a source, with a chunk of lookahead. One chunk is the most this
/// ever holds beyond the header, which is the most the format needs.
priv struct Reader {
  source : &Source
  mut held : Bytes
  mut at : Int32
  mut eof : Bool
}

///|
fn Reader::new(source : &Source) -> Self {
  { source, held: b"", at: 0, eof: false, }
}

///|
fn Reader::available(self : Reader) -> Int32 {
  self.held.length() - self.at
}

///|
fn Reader::view(self : Reader) -> BytesView {
  self.held.clamped_view(start=self.at)
}

///|
/// Pull until at least `want` bytes are buffered, or the source is spent.
fn Reader::fill(self : Reader, want~ : Int32) -> Unit raise @spec.Refused {
  while self.available() < want && !self.eof {
    let piece = self.source.read(limit=@stream.chunk)
    if piece.length() == 0 {
      self.eof = true
      break
    }
    if self.at > 0 {
      self.held = self.held.clamped_view(start=self.at).to_owned()
      self.at = 0
    }
    self.held = self.held.add(piece)
  }
}

///|
fn Reader::take(self : Reader, len~ : Int32) -> Bytes {
  let piece = self.view().clamped_view(end=len).to_owned()
  self.at = self.at + len
  piece
}

///|
/// Read a header from a source: everything up to and including the line feed
/// after the MAC, which is where the payload starts.
///
/// The end is found by looking for the first `---` at the start of a line, which
/// no stanza body can be confused for: a body line is base64, and `-` is not in
/// that alphabet.
fn read_header(reader : Reader) -> Bytes raise @spec.Refused {
  let mut want = 256
  while true {
    reader.fill(want~)
    let view = reader.view()
    if view.length() > @header.limit {
      raise @spec.Refused::Limit(want=@header.limit, got=view.length())
    }
    let found = match view.find(b"\n--- ") {
      Some(mark) => view.clamped_view(start=mark + 1).find(b"\n")
      None => None
    }
    match found {
      Some(rest) => {
        let end = view.find(b"\n--- ").unwrap_or(0) + 1 + rest + 1
        let text = view.clamped_view(end~).to_owned()
        ignore(reader.take(len=end))
        return text
      }
      None => ()
    }
    if reader.eof {
      // Whatever is there is a header that never ended; asking the parser what is
      // wrong with it gives a better refusal than "unexpected end".
      ignore(@header.Header::decode(view))
      raise @spec.Refused::Header(
        at=view.length(),
        want="the end of the header",
      )
    }
    want = view.length() + @stream.chunk
  }
  abort("unreachable")
}

///|
/// A sink that writes the file out as armored text.
priv struct ArmoredSink {
  sink : &Sink
  encoder : @armor.Encoder
  mut started : Bool
}

///|
fn ArmoredSink::new(sink : &Sink) -> Self {
  { sink, encoder: @armor.Encoder::new(), started: false, }
}

///|
fn ArmoredSink::finish(self : ArmoredSink) -> Unit raise @spec.Refused {
  self.start()
  let text = self.encoder.finish()
  self.sink.write(bytes=@utf8.encode(text))
}

///|
fn ArmoredSink::start(self : ArmoredSink) -> Unit raise @spec.Refused {
  if !self.started {
    self.started = true
    self.sink.write(bytes=@utf8.encode(@armor.head()))
  }
}

///|
impl Sink for ArmoredSink with fn write(self, bytes~) {
  self.start()
  let text = self.encoder.write(bytes)
  if text.length() > 0 {
    self.sink.write(bytes=@utf8.encode(text))
  }
}

///|
/// A source that decodes an armored text block and hands out the file.
priv struct ArmoredSource {
  source : &Source
  decoder : @armor.Decoder
  mut pending : Bytes
  mut done : Bool
}

///|
fn ArmoredSource::new(source : &Source) -> Self {
  { source, decoder: @armor.Decoder::new(), pending: b"", done: false, }
}

///|
impl Source for ArmoredSource with fn read(self, limit~) {
  while true {
    if self.pending.length() > 0 {
      let take = if self.pending.length() < limit {
        self.pending.length()
      } else {
        limit
      }
      let piece = self.pending.clamped_view(end=take).to_owned()
      self.pending = self.pending.clamped_view(start=take).to_owned()
      return piece
    }
    if self.done {
      return b""
    }
    let text = self.source.read(limit=@stream.chunk)
    if text.length() > 0 {
      self.decoder.push(@utf8.decode_lossy(text))
      self.pending = self.decoder.take()
      continue
    }
    self.pending = self.decoder.finish()
    self.done = true
  }
  b""
}
