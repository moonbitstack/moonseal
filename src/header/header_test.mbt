// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A stanza with a body of `len` bytes, which is what the wrapping rules are
/// about: a body whose base64 fills a line exactly needs a line of its own to
/// close it.
fn stanza(kind : String, body : Bytes) -> @spec.Stanza {
  @spec.Stanza::new(kind~, args=[], body~)
}

///|
test "a header round trips through its own bytes" {
  let key = Bytes::make(16, 0x11)
  let stanzas = [
    @spec.Stanza::new(
      kind="X25519",
      args=["abc", "def"],
      body=Bytes::make(32, 1),
    ),
    @spec.Stanza::new(
      kind="example.com/enigma",
      args=[],
      body=Bytes::make(0, 0),
    ),
    stanza("X25519", Bytes::make(48, 2)),
    stanza("X25519", Bytes::make(49, 3)),
    stanza("X25519", Bytes::make(96, 4)),
  ]
  let head = @header.Header::new(stanzas)
  let text = head.encode(file_key=key)
  let (back, at) = @header.Header::decode(text) catch {
    error => fail("cannot read back what we wrote: \{error}")
  }
  assert_eq(at, text.length())
  assert_eq(back.stanzas().length(), 5)
  assert_eq(back.stanzas()[0].args, ["abc", "def"])
  assert_eq(back.stanzas()[1].body.length(), 0)
  back.verify(file_key=key)
}

///|
/// The body is wrapped at 48 bytes, so a body of exactly 48 ends with a line of
/// 64 columns and needs one more, shorter line to close it. Everything the
/// reader accepts has to be written that way.
test "a body that fills a line is still closed" {
  let text = @header.Header::new([stanza("X25519", Bytes::make(48, 0xAA))]).encode(
    file_key=Bytes::make(16, 0),
  )
  let lines = @utf8.decode_lossy(text).split("\n").collect()
  // The version line, the stanza line, one full body line, its empty closure,
  // and the MAC line — with a trailing empty piece after the last line feed.
  assert_eq(lines.length(), 6)
  assert_eq(lines[2].length(), 64)
  assert_eq(lines[3].length(), 0)
}

///|
test "a header that has been edited does not verify" {
  let key = Bytes::make(16, 0x22)
  let text = @header.Header::new([stanza("X25519", Bytes::make(32, 0xFF))]).encode(
    file_key=key,
  )
  let (head, _) = @header.Header::decode(text) catch { _ => abort("no") }
  head.verify(file_key=key)
  // One character of the body, which is all an editor needs to change who a file
  // is for.
  let bytes = text.to_array()
  bytes[34] = if bytes[34] == b'A' { b'B' } else { b'A' }
  let (edited, _) = @header.Header::decode(Bytes::from_array(bytes)) catch {
    _ => abort("no")
  }
  let caught = try {
    edited.verify(file_key=key)
    false
  } catch {
    @spec.Refused::Mac => true
    _ => false
  }
  assert_true(caught)
  // And the same header under the wrong key does not verify either.
  let caught = try {
    head.verify(file_key=Bytes::make(16, 0x99))
    false
  } catch {
    @spec.Refused::Mac => true
    _ => false
  }
  assert_true(caught)
}

///|
test "a header with nothing in it is not written" {
  let refused = try {
    ignore(@header.Header::new([]))
    false
  } catch {
    @spec.Refused::Header(at~, ..) => {
      assert_eq(at, 0)
      true
    }
    _ => false
  }
  assert_true(refused)
}

///|
/// A passphrase stanza is alone, on the way out and on the way in: a file that
/// says otherwise was not written by anybody who read the format.
test "a passphrase stanza will not share a header" {
  let key = Bytes::make(16, 0x33)
  let mixed = [
    stanza("scrypt", Bytes::make(32, 1)),
    stanza("X25519", Bytes::make(32, 2)),
  ]
  let refused = try {
    ignore(@header.Header::new(mixed))
    false
  } catch {
    @spec.Refused::Header(..) => true
    _ => false
  }
  assert_true(refused)
  // And the same rule on the way in, from bytes nobody here wrote.
  let text = @header.Header::new([stanza("X25519", Bytes::make(32, 2))]).encode(
    file_key=key,
  )
  let lines = @utf8.decode_lossy(text).split("\n").collect()
  let spliced = "age-encryption.org/v1\n" +
    "-> scrypt AAAAAAAAAAAAAAAAAAAAAA 10\n" +
    lines[1].to_owned() +
    "\n" +
    lines[2].to_owned() +
    "\n" +
    lines[3].to_owned()
  let refused = try {
    ignore(@header.Header::decode(@utf8.encode(spliced)))
    false
  } catch {
    @spec.Refused::Header(..) => true
    _ => false
  }
  assert_true(refused)
}

///|
test "a header that is not this format is refused" {
  let cases = [
    // Nothing at all.
    "",
    // The right words, the wrong version.
     "age-encryption.org/v2\n",
    // A version line that ends in a carriage return.
     "age-encryption.org/v1\r\n",
    // A stanza that never ends.
     "age-encryption.org/v1\n-> X25519 ab\n",
    // A MAC line with no space.
     "age-encryption.org/v1\n-> X25519 ab\n\n---abc\n",
    // A MAC line that is not forty-three characters.
     "age-encryption.org/v1\n-> X25519 ab\n\n--- abc\n",
  ]
  for case in cases {
    let refused = try {
      ignore(@header.Header::decode(@utf8.encode(case)))
      false
    } catch {
      @spec.Refused::Header(..) => true
      _ => false
    }
    assert_true(refused)
  }
}

///|
test "an argument with a space in it is two arguments" {
  let text = @header.Header::new([
    @spec.Stanza::new(kind="X25519", args=["a b"], body=Bytes::make(32, 0)),
  ]).encode(file_key=Bytes::make(16, 0))
  let (head, _) = @header.Header::decode(text) catch { _ => abort("no") }
  assert_eq(head.stanzas()[0].args, ["a", "b"])
}

///|
test "the offset a header ends at is where the payload begins" {
  let key = Bytes::make(16, 0x44)
  let text = @header.Header::new([stanza("X25519", Bytes::make(32, 9))]).encode(
    file_key=key,
  )
  let both = text.add(b"payload")
  let (_, at) = @header.Header::decode(both) catch { _ => abort("no") }
  assert_eq(at, text.length())
}
