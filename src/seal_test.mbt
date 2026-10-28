// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Randomness that is the same every time, so that two runs can be compared.
fn pool(bytes : Int32, seed : Int32) -> @spec.Entropy {
  @spec.Entropy::new(
    Bytes::from_array(
      Array::makei(bytes, fn(i) { ((i * 31 + seed * 17) % 256).to_byte() }),
    ),
  )
}

///|
fn alice() -> @x25519.Identity {
  @x25519.Identity::new(Bytes::make(32, 0xA1)) catch {
    _ => abort("no")
  }
}

///|
fn bob() -> @x25519.Identity {
  @x25519.Identity::new(Bytes::make(32, 0xB2)) catch {
    _ => abort("no")
  }
}

///|
test "a file for several readers opens for each of them" {
  let recipients : Array[&@spec.Recipient] = [alice().public(), bob().public()]
  let file = @moonseal.seal(
    recipients,
    b"for both of you",
    entropy=pool(128, 1),
  ) catch {
    error => fail("cannot seal: \{error}")
  }
  for identity in [alice(), bob()] {
    let identities : Array[&@spec.Identity] = [identity]
    assert_eq(
      @moonseal.open(identities, file),
      b"for both of you",
      msg="for " + identity.code(),
    )
  }
}

///|
test "a file addressed to somebody else does not open" {
  let strangers : Array[&@spec.Identity] = [
    @x25519.Identity::new(Bytes::make(32, 0xC3)) catch {
      _ => abort("no")
    },
  ]
  let recipients : Array[&@spec.Recipient] = [alice().public()]
  let file = @moonseal.seal(recipients, b"secret", entropy=pool(128, 2)) catch {
    _ => abort("no")
  }
  let refused = try {
    ignore(@moonseal.open(strangers, file))
    false
  } catch {
    @spec.Refused::NoMatch => true
    _ => false
  }
  assert_true(refused)
}

///|
test "the empty file and the long file both round trip" {
  for
    size in [
      0,
      1,
      @stream.chunk - 1,
      @stream.chunk,
      @stream.chunk + 1,
      3 * @stream.chunk,
    ] {
    let plain = Bytes::make(size, 0x5C)
    let recipients : Array[&@spec.Recipient] = [alice().public()]
    let file = @moonseal.seal(recipients, plain, entropy=pool(128, 3)) catch {
      error => fail("cannot seal \{size} bytes: \{error}")
    }
    let identities : Array[&@spec.Identity] = [alice()]
    assert_eq(@moonseal.open(identities, file), plain, msg="at \{size} bytes")
  }
}

///|
/// One edited byte of the payload is caught, and caught before it is written out:
/// the chunk it belongs to does not authenticate.
test "an edited payload does not open" {
  let recipients : Array[&@spec.Recipient] = [alice().public()]
  let file = @moonseal.seal(recipients, b"a message", entropy=pool(128, 4)) catch {
    _ => abort("no")
  }
  let bytes = file.to_array()
  bytes[bytes.length() - 1] = if bytes[bytes.length() - 1] == b'A' {
    b'B'
  } else {
    b'A'
  }
  let identities : Array[&@spec.Identity] = [alice()]
  let refused = try {
    ignore(@moonseal.open(identities, Bytes::from_array(bytes)))
    false
  } catch {
    @spec.Refused::Payload(..) => true
    _ => false
  }
  assert_true(refused)
}

///|
/// A header that has been added to is caught by the MAC, which is the only thing
/// standing between a file and a second reader somebody else added on the way.
test "an edited header does not open" {
  let recipients : Array[&@spec.Recipient] = [alice().public()]
  let file = @moonseal.seal(recipients, b"a message", entropy=pool(128, 5)) catch {
    _ => abort("no")
  }
  // The MAC line is the last thing in the header, so it ends where the header
  // does; one character of it is enough.
  let (_, at) = @header.Header::decode(file) catch { _ => abort("no") }
  let bytes = file.to_array()
  let last = at - 5
  bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' }
  let identities : Array[&@spec.Identity] = [alice()]
  let refused = try {
    ignore(@moonseal.open(identities, Bytes::from_array(bytes)))
    false
  } catch {
    @spec.Refused::Mac => true
    _ => false
  }
  assert_true(refused)
}

///|
test "too little randomness is refused before anything is written" {
  let recipients : Array[&@spec.Recipient] = [alice().public()]
  let refused = try {
    // Sixteen for the file key, thirty-two for the share, sixteen for the nonce.
    ignore(@moonseal.seal(recipients, b"x", entropy=pool(63, 6)))
    false
  } catch {
    @spec.Refused::Entropy(want~, got~) => {
      assert_eq(want, 16)
      assert_eq(got, 15)
      true
    }
    _ => false
  }
  assert_true(refused)
}

///|
/// The streaming form has to produce exactly the bytes the in-memory form does,
/// or a file sealed by one would not open with the other.
test "the stream and the buffer agree" {
  let plain = Bytes::make(2 * @stream.chunk + 7, 0x6D)
  let recipients : Array[&@spec.Recipient] = [alice().public()]
  let in_memory = @moonseal.seal(recipients, plain, entropy=pool(128, 7)) catch {
    _ => abort("no")
  }
  let sink = @moonseal.BytesSink::new()
  @moonseal.seal_stream(
    sink,
    recipients,
    @moonseal.BytesSource::new(plain),
    entropy=pool(128, 7),
  ) catch {
    error => fail("cannot stream: \{error}")
  }
  assert_eq(sink.bytes(), in_memory)
  // And back out again, through the streaming reader.
  let out = @moonseal.BytesSink::new()
  let identities : Array[&@spec.Identity] = [alice()]
  @moonseal.open_stream(out, identities, @moonseal.BytesSource::new(in_memory)) catch {
    error => fail("cannot open the stream: \{error}")
  }
  assert_eq(out.bytes(), plain)
}

///|
/// A source that hands over a byte at a time is a legal source, and the reader
/// has to keep asking.
test "a source that gives a byte at a time is read the same" {
  let plain = Bytes::make(@stream.chunk + 100, 0x7E)
  let recipients : Array[&@spec.Recipient] = [alice().public()]
  let file = @moonseal.seal(recipients, plain, entropy=pool(128, 8)) catch {
    _ => abort("no")
  }
  let out = @moonseal.BytesSink::new()
  let identities : Array[&@spec.Identity] = [alice()]
  @moonseal.open_stream(out, identities, Trickle::new(file)) catch {
    error => fail("cannot open a trickled file: \{error}")
  }
  assert_eq(out.bytes(), plain)
}

///|
/// A source that answers one byte however much it is asked for.
struct Trickle {
  bytes : Bytes
  mut at : Int32
}

///|
fn Trickle::new(bytes : BytesView) -> Self {
  { bytes: bytes.to_owned(), at: 0, }
}

///|
impl @moonseal.Source for Trickle with fn read(self, limit~) {
  ignore(limit)
  if self.at >= self.bytes.length() {
    return b""
  }
  let piece = self.bytes.clamped_view(start=self.at, end=self.at + 1).to_owned()
  self.at = self.at + 1
  piece
}

///|
test "an armored file round trips, in memory and in a stream" {
  let plain = Bytes::make(100, 0x2B)
  let recipients : Array[&@spec.Recipient] = [alice().public()]
  let text = @moonseal.seal_armored(recipients, plain, entropy=pool(128, 9)) catch {
    error => fail("cannot seal: \{error}")
  }
  let identities : Array[&@spec.Identity] = [alice()]
  assert_eq(@moonseal.open_armored(identities, text), plain)
  // The streamed armor is the same text.
  let sink = @moonseal.BytesSink::new()
  @moonseal.seal_stream_armored(
    sink,
    recipients,
    @moonseal.BytesSource::new(plain),
    entropy=pool(128, 9),
  ) catch {
    error => fail("cannot stream armor: \{error}")
  }
  assert_eq(@utf8.decode_lossy(sink.bytes()), text)
  // And the streamed reader takes it.
  let out = @moonseal.BytesSink::new()
  @moonseal.open_stream_armored(
    out,
    identities,
    @moonseal.BytesSource::new(sink.bytes()),
  ) catch {
    error => fail("cannot open streamed armor: \{error}")
  }
  assert_eq(out.bytes(), plain)
}

///|
/// A recipient type nobody here has heard of: the body is the file key with
/// nothing around it.
///
/// This is not a design to use — it hands the file key to anybody who reads the
/// header. It is the smallest thing that satisfies the two methods, and it is
/// here to show that a type of one's own travels through this library without a
/// line of it changing: the header carries the stanza, and the other recipients
/// never look at it.
struct Echo {}

///|
impl @spec.Recipient for Echo with fn wrap(self, file_key~, entropy~) {
  ignore(self)
  ignore(entropy)
  @spec.Stanza::new(kind="example.com/echo", args=[], body=file_key.to_owned())
}

///|
impl @spec.Identity for Echo with fn unwrap(self, stanza~) {
  ignore(self)
  if stanza.kind == "example.com/echo" {
    return Some(stanza.body)
  }
  None
}

///|
test "a recipient type of one's own plugs in" {
  let echo = Echo::{ }
  let recipients : Array[&@spec.Recipient] = [echo, alice().public()]
  let file = @moonseal.seal(recipients, b"hello", entropy=pool(128, 10)) catch {
    error => fail("cannot seal: \{error}")
  }
  // The type we wrote opens it.
  let mine : Array[&@spec.Identity] = [echo]
  assert_eq(@moonseal.open(mine, file), b"hello")
  // And so does the one next to it, which never saw that stanza type.
  let theirs : Array[&@spec.Identity] = [alice()]
  assert_eq(@moonseal.open(theirs, file), b"hello")
}

///|
test "a file that is not a file is refused" {
  let identities : Array[&@spec.Identity] = [alice()]
  for case in [b"", b"hello", b"age-encryption.org/v2\n"] {
    let refused = try {
      ignore(@moonseal.open(identities, case))
      false
    } catch {
      @spec.Refused::Header(..) => true
      _ => false
    }
    assert_true(refused)
  }
  let refused = try {
    ignore(@moonseal.open_armored(identities, "not an armored file"))
    false
  } catch {
    @spec.Refused::Armor(..) => true
    _ => false
  }
  assert_true(refused)
}
