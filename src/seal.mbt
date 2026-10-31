// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The file key: sixteen bytes, fresh for every file, never written anywhere.
///
/// Sixteen is the format's number, and it is small on purpose — the payload key
/// and the header MAC are both derived from it, so its length is not what stands
/// between a file and a guess.
let file_key_size : Int32 = 16

///|
/// Where bytes come from. A file, a socket, a buffer: anything that can hand over
/// a run of bytes and say when it has no more.
///
/// `read` may return fewer bytes than it was asked for; an empty answer means the
/// end. The reader in this library asks for a chunk at a time and keeps asking
/// until it has what it needs or the source is spent.
pub(open) trait Source {
  fn read(Self, limit~ : Int32) -> Bytes raise @spec.Refused
}

///|
/// Where bytes go. It may be called with small pieces, and it is called in the
/// order the file is written.
pub(open) trait Sink {
  fn write(Self, bytes~ : BytesView) -> Unit raise @spec.Refused
}

///|
/// A source over bytes that are already in memory, which is what a caller with a
/// file in a buffer wants, and what the tests use.
pub struct BytesSource {
  priv bytes : Bytes
  priv mut at : Int32
}

///|
pub fn BytesSource::new(bytes : BytesView) -> Self {
  { bytes: bytes.to_owned(), at: 0, }
}

///|
pub extend BytesSource with Source::{read}

///|
pub impl Source for BytesSource with fn read(self, limit~) {
  let left = self.bytes.length() - self.at
  let take = if left < limit { left } else { limit }
  let piece = self.bytes.clamped_view(start=self.at, end=self.at + take)
  self.at = self.at + take
  piece.to_owned()
}

///|
/// The whole of a source, which is what a caller does when the input is small
/// enough to hold and they would rather see it than stream it.
pub fn drain(source : &Source) -> Bytes raise @spec.Refused {
  let out = @buffer.Buffer(size_hint=4096)
  while true {
    let piece = source.read(limit=@stream.chunk)
    if piece.length() == 0 {
      break
    }
    out.write_bytes(piece)
  }
  out.to_bytes()
}

///|
/// A sink over a buffer, for the same reason.
pub struct BytesSink {
  priv buffer : @buffer.Buffer
}

///|
pub fn BytesSink::new() -> Self {
  { buffer: @buffer.Buffer(size_hint=4096), }
}

///|
/// Everything written so far, as one byte string.
pub fn BytesSink::bytes(self : BytesSink) -> Bytes {
  self.buffer.to_bytes()
}

///|
pub extend BytesSink with Sink::{write}

///|
pub impl Sink for BytesSink with fn write(self, bytes~) {
  self.buffer.write_bytes(bytes)
}

///|
/// Seal `plain` for `recipients`, and give back the file.
///
/// The file key, every stanza's ephemeral material and the payload nonce come
/// out of `random`, in that order: `@system.source` from `moonseed/system` in a
/// program, a `Replay` of fixed bytes in a test that wants the same file twice.
/// A source that fails is a refusal, and it arrives before the first byte is
/// written.
///
/// How much a file draws: sixteen bytes for the file key, then thirty-two for
/// each X25519 recipient and sixteen for each scrypt recipient, then sixteen for
/// the payload nonce.
pub fn seal(
  recipients : Array[&@spec.Recipient],
  plain : BytesView,
  random~ : &@moonseed.Source,
) -> Bytes raise @spec.Refused {
  let file_key = @spec.draw(random, file_key_size)
  let stanzas = Array(capacity=recipients.length())
  for recipient in recipients {
    stanzas.push(recipient.wrap(file_key~, random~))
  }
  let nonce = @spec.draw(random, @stream.nonce)
  let head = @header.Header::new(stanzas)
  let out = @buffer.Buffer(size_hint=plain.length() + 1024)
  out.write_bytes(head.encode(file_key~))
  out.write_bytes(nonce)
  let sealer = @stream.Sealer::new(key=@stream.payload_key(file_key~, nonce~))
  let mut at = 0
  while plain.length() - at > @stream.chunk {
    let piece = plain.clamped_view(start=at, end=at + @stream.chunk)
    out.write_bytes(sealer.chunk(plain=piece, last=false))
    at = at + @stream.chunk
  }
  let rest = plain.clamped_view(start=at)
  out.write_bytes(sealer.chunk(plain=rest, last=true))
  out.to_bytes()
}

///|
/// The same as `seal`, written out as an armored text block.
pub fn seal_armored(
  recipients : Array[&@spec.Recipient],
  plain : BytesView,
  random~ : &@moonseed.Source,
) -> String raise @spec.Refused {
  @armor.encode(seal(recipients, plain, random~))
}

///|
/// Open a file addressed to any one of `identities`.
///
/// The header is checked before the payload is touched: a stanza is opened to
/// recover the file key, the MAC over the header is verified with it, and only
/// then does a chunk get decrypted. A header that does not verify means somebody
/// edited the list of who can read the file, and no part of the payload is worth
/// looking at after that.
pub fn open(
  identities : Array[&@spec.Identity],
  cipher : BytesView,
) -> Bytes raise @spec.Refused {
  let (head, at) = @header.Header::decode(cipher)
  let file_key = file_key_of(identities, head)
  return payload(cipher.clamped_view(start=at), file_key)
}

///|
/// Open an armored block.
pub fn open_armored(
  identities : Array[&@spec.Identity],
  text : StringView,
) -> Bytes raise @spec.Refused {
  open(identities, @armor.decode(text))
}

///|
/// The file key, from whichever identity recognises a stanza.
///
/// The first stanza that opens settles it: the file key is the same in every
/// stanza, so a MAC that fails after one has opened is a broken file rather than
/// a reason to keep trying.
fn file_key_of(
  identities : Array[&@spec.Identity],
  head : @header.Header,
) -> Bytes raise @spec.Refused {
  for stanza in head.stanzas() {
    for identity in identities {
      match identity.unwrap(stanza~) {
        Some(file_key) => {
          if file_key.length() != file_key_size {
            raise @spec.Refused::Key(want=file_key_size, got=file_key.length())
          }
          head.verify(file_key~)
          return file_key
        }
        None => ()
      }
    }
  }
  raise @spec.Refused::NoMatch
}

///|
/// The payload, from the nonce to the last chunk.
fn payload(
  bytes : BytesView,
  file_key : BytesView,
) -> Bytes raise @spec.Refused {
  // A file that stops before its nonce never had a payload: nothing has been
  // written out at this point, so it is a header that promised more than the
  // file delivered.
  if bytes.length() < @stream.nonce {
    raise @spec.Refused::Header(
      at=bytes.length(),
      want="a 16-byte payload nonce",
    )
  }
  let nonce = bytes.clamped_view(end=@stream.nonce)
  let opener = @stream.Opener::new(key=@stream.payload_key(file_key~, nonce~))
  let body = bytes.clamped_view(start=@stream.nonce)
  let out = @buffer.Buffer(size_hint=body.length())
  let mut base = 0
  while true {
    let left = body.length() - base
    // A payload ends with a chunk that says so. Running out of bytes first is a
    // truncated file, not a short one.
    if left == 0 {
      raise @spec.Refused::Payload(at=@stream.nonce + base)
    }
    let last = left <= @stream.chunk + @stream.tag
    let take = if last { left } else { @stream.chunk + @stream.tag }
    let piece = opener.chunk(
      cipher=body.clamped_view(start=base, end=base + take),
      last~,
    ) catch {
      @spec.Refused::Payload(at~) =>
        raise @spec.Refused::Payload(at=@stream.nonce + at)
      error => raise error
    }
    out.write_bytes(piece)
    base = base + take
    if last {
      break
    }
  }
  out.to_bytes()
}
