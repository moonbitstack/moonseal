// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// How much plaintext one chunk holds.
pub let chunk : Int32 = 64 * 1024

///|
/// How many bytes a chunk grows by, which is the size of an authentication tag.
pub let tag : Int32 = @crypt.tag_size

///|
/// How many bytes of nonce precede the first chunk. It is drawn once per file,
/// and the payload key is derived from it, which is what makes two files sealed
/// under the same recipients differ from the first byte.
pub let nonce : Int32 = 16

///|
/// The payload key: the file key, salted with the payload nonce.
pub fn payload_key(file_key~ : BytesView, nonce~ : BytesView) -> Bytes {
  @crypt.hkdf(file_key, nonce, b"payload", len=32)
}

///|
/// The nonce for one chunk: an eleven-byte counter, big-endian, then a byte that
/// is one for the last chunk and zero for every other.
///
/// The flag is what stops a payload from being truncated: a chunk that was the
/// last one cannot be passed off as one that was not, and a reader that reaches
/// the end without seeing a final chunk has an error rather than a shorter file.
fn nonce_for(counter : FixedArray[Byte], last~ : Bool) -> Bytes {
  let out = Array(capacity=12)
  for i in 0..<11 {
    out.push(counter[i])
  }
  out.push(if last { b'\x01' } else { b'\x00' })
  Bytes::from_array(out)
}

///|
/// Advance an eleven-byte big-endian counter by one, which is the whole of the
/// chunk numbering.
fn step(counter : FixedArray[Byte]) -> Unit {
  let mut i = 10
  while i >= 0 {
    let next = counter[i].to_int() + 1
    counter[i] = (next & 0xFF).to_byte()
    if next < 256 {
      break
    }
    i = i - 1
  }
}

///|
/// A payload writer: holds the key, and remembers which chunk comes next.
pub struct Sealer {
  priv key : Bytes
  priv counter : FixedArray[Byte]
  priv mut chunks : Int32
}

///|
/// A sealer over a payload key of thirty-two bytes.
pub fn Sealer::new(key~ : BytesView) -> Self raise @spec.Refused {
  if key.length() != @crypt.key_size {
    raise @spec.Refused::Entropy(want=@crypt.key_size, got=key.length())
  }
  { key: key.to_owned(), counter: FixedArray::make(11, b'\x00'), chunks: 0, }
}

///|
/// How many chunks have been sealed, which is how many the payload will hold.
pub fn Sealer::chunks(self : Sealer) -> Int32 {
  self.chunks
}

///|
/// Seal one chunk. `last` marks the end of the payload; a payload of no bytes at
/// all is still one chunk — an empty one — whose tag is the only thing standing
/// between an empty file and a truncated one.
pub fn Sealer::chunk(self : Sealer, plain~ : BytesView, last~ : Bool) -> Bytes {
  if plain.length() > chunk {
    abort("stream: a chunk is at most \{chunk} bytes")
  }
  if !last && plain.length() != chunk {
    abort("stream: only the last chunk may be shorter than \{chunk} bytes")
  }
  let out = @crypt.seal(self.key[:], nonce_for(self.counter, last~), plain)
  step(self.counter)
  self.chunks = self.chunks + 1
  out
}

///|
/// A payload reader: holds the key, and checks that chunks arrive in order and
/// that the last one says it is the last.
pub struct Opener {
  priv key : Bytes
  priv counter : FixedArray[Byte]
  priv mut chunks : Int32
  priv mut consumed : Int32
  priv mut last : Bool
}

///|
pub fn Opener::new(key~ : BytesView) -> Self raise @spec.Refused {
  if key.length() != @crypt.key_size {
    raise @spec.Refused::Entropy(want=@crypt.key_size, got=key.length())
  }
  {
    key: key.to_owned(),
    counter: FixedArray::make(11, b'\x00'),
    chunks: 0,
    consumed: 0,
    last: false,
  }
}

///|
/// How many chunks have been opened.
pub fn Opener::chunks(self : Opener) -> Int32 {
  self.chunks
}

///|
/// Whether the payload ended: a payload is only over once a chunk said it was
/// the last one, so a reader that runs out of bytes first has been handed a
/// truncated file.
pub fn Opener::done(self : Opener) -> Bool {
  self.last
}

///|
/// Open one chunk, or refuse it. The refusal carries the offset of the chunk
/// from the start of the payload.
pub fn Opener::chunk(
  self : Opener,
  cipher~ : BytesView,
  last~ : Bool,
) -> Bytes raise @spec.Refused {
  let at = self.chunks * (chunk + tag)
  if cipher.length() < tag {
    raise @spec.Refused::Payload(at~)
  }
  if cipher.length() > chunk + tag {
    raise @spec.Refused::Payload(at~)
  }
  if !last && cipher.length() != chunk + tag {
    raise @spec.Refused::Payload(at~)
  }
  // An empty chunk is how an empty payload is written, and it is only that: a
  // chunk with nothing in it in the middle of a file would let a payload be
  // padded, so it is refused before it is decrypted.
  if last && cipher.length() == tag && self.chunks > 0 {
    raise @spec.Refused::Payload(at~)
  }
  let plain = @crypt.open(self.key[:], nonce_for(self.counter, last~), cipher)
  step(self.counter)
  self.chunks = self.chunks + 1
  self.consumed = self.consumed + cipher.length()
  self.last = last
  match plain {
    None => raise @spec.Refused::Payload(at~)
    Some(bytes) => bytes
  }
}
