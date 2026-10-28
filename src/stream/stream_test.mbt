// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A payload key, which is any thirty-two bytes here: this package knows nothing
/// about where a key came from.
fn key() -> Bytes {
  Bytes::make(32, 0x5A)
}

///|
/// The payload for `plain`, chunked the way the format says.
fn seal(plain : BytesView) -> Array[Bytes] {
  let sealer = @stream.Sealer::new(key=key()) catch { _ => abort("no") }
  let out = Array(capacity=plain.length() / @stream.chunk + 1)
  if plain.length() == 0 {
    out.push(sealer.chunk(plain=b""[:], last=true))
    return out
  }
  let mut at = 0
  while plain.length() - at > @stream.chunk {
    out.push(
      sealer.chunk(
        plain=plain.clamped_view(start=at, end=at + @stream.chunk),
        last=false,
      ),
    )
    at = at + @stream.chunk
  }
  out.push(sealer.chunk(plain=plain.clamped_view(start=at), last=true))
  out
}

///|
/// Open a list of chunks, and give back what came out.
fn open(chunks : Array[Bytes]) -> Bytes raise @spec.Refused {
  let opener = @stream.Opener::new(key=key()) catch { _ => abort("no") }
  let out = @buffer.Buffer(size_hint=1024)
  for i, chunk in chunks {
    out.write_bytes(opener.chunk(cipher=chunk, last=i == chunks.length() - 1))
  }
  out.to_bytes()
}

///|
/// Every place a chunk boundary can fall, including the two that a naive reader
/// gets wrong: exactly one chunk, and one chunk plus a byte.
test "a payload round trips at every boundary" {
  let sizes = [
    0,
    1,
    15,
    16,
    17,
    1000,
    @stream.chunk - 1,
    @stream.chunk,
    @stream.chunk + 1,
    2 * @stream.chunk,
    2 * @stream.chunk + 1,
  ]
  for size in sizes {
    let plain = Bytes::make(size, 0x2A)
    let chunks = seal(plain)
    assert_eq(open(chunks), plain, msg="at \{size} bytes")
  }
}

///|
test "a payload of nothing is still a chunk" {
  let chunks = seal(b"")
  assert_eq(chunks.length(), 1)
  assert_eq(chunks[0].length(), @stream.tag)
  assert_eq(open(chunks), b"")
}

///|
/// A reader that is given the chunks out of order must not silently assemble
/// them: the counter in the nonce is what catches this.
test "chunks out of order do not open" {
  let plain = Bytes::make(2 * @stream.chunk + 100, 0x31)
  let chunks = seal(plain)
  let swapped = [chunks[1], chunks[0], chunks[2]]
  let caught = try {
    ignore(open(swapped))
    false
  } catch {
    @spec.Refused::Payload(..) => true
    _ => false
  }
  assert_true(caught)
}

///|
/// The last chunk says it is the last, so a file cut short is refused rather
/// than read as a shorter file.
test "a payload with its tail cut off does not open" {
  let plain = Bytes::make(@stream.chunk + 100, 0x42)
  let chunks = seal(plain)
  let caught = try {
    ignore(open([chunks[0]]))
    false
  } catch {
    @spec.Refused::Payload(..) => true
    _ => false
  }
  assert_true(caught)
}

///|
test "the wrong key opens nothing" {
  let chunks = seal(b"hello")
  let opener = @stream.Opener::new(key=Bytes::make(32, 0x5B)) catch {
    _ => abort("no")
  }
  let caught = try {
    ignore(opener.chunk(cipher=chunks[0], last=true))
    false
  } catch {
    @spec.Refused::Payload(..) => true
    _ => false
  }
  assert_true(caught)
}

///|
test "panic a chunk longer than a chunk" {
  let sealer = @stream.Sealer::new(key=key()) catch { _ => abort("no") }
  ignore(sealer.chunk(plain=Bytes::make(@stream.chunk + 1, 0), last=true))
}

///|
test "panic a short chunk that is not the last" {
  let sealer = @stream.Sealer::new(key=key()) catch { _ => abort("no") }
  ignore(sealer.chunk(plain=Bytes::make(10, 0), last=false))
}

///|
test "panic a key of the wrong size" {
  ignore(@stream.Sealer::new(key=Bytes::make(16, 0)))
}

///|
/// The counter is eleven bytes big-endian, so chunk 256 is the first one whose
/// second byte moves. A reader that counted in four bytes would agree with
/// itself and with nothing else.
test "the chunk counter carries past 255" {
  let sealer = @stream.Sealer::new(key=key()) catch { _ => abort("no") }
  let filler = Bytes::make(@stream.chunk, 0x11)
  let chunks = Array(capacity=258)
  for i in 0..<258 {
    chunks.push(sealer.chunk(plain=filler, last=i == 257))
  }
  let opener = @stream.Opener::new(key=key()) catch { _ => abort("no") }
  let mut total = 0
  for i, chunk in chunks {
    total = total + opener.chunk(cipher=chunk, last=i == 257).length()
  }
  assert_eq(total, 258 * @stream.chunk)
}
