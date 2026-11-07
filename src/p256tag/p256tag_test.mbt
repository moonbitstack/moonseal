// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The string the age test plugin is named after, which its identity is derived
/// from. Every published value below follows from these bytes.
let seed : Bytes = b"age-plugin-tagtest"

///|
/// That identity's public half, as the reference implementation writes it.
let published : String = "age1tag1qwe0kafsjrar4txm6heqnhpfuggzr0gvznz7fvygxrlq90u5mq2pysxtw6h"

///|
/// The scalar the same derivation produces, in the reference implementation's
/// bytes: the check that both sides arrive at a key and not merely at a string.
let scalar_hex : String = "8dc9e8b609a4b6e8d8b41b853c64668789104b156ae642193a575f4b3f6b9148"

///|
/// Randomness that is the same every time, so that a failure is a failure of the
/// format rather than of a draw.
fn pool() -> @moonseed.Replay {
  @moonseed.Replay::new(
    Bytes::from_array(
      Array::makei(512, fn(i) { ((i * 37 + 11) % 256).to_byte() }),
    ),
  )
}

///|
/// The identity behind the published recipient.
fn identity() -> @p256tag.Identity {
  @p256tag.Identity::from_seed(seed[:]) catch {
    error => abort("the seed does not derive: \{error}")
  }
}

///|
/// Sixty-five bytes with an uncompressed-point prefix, which is what an
/// encapsulation looks like.
fn encapsulation() -> Bytes {
  let out = Array::makei(65, fn(i) { i.to_byte() })
  out[0] = b'\x04'
  Bytes::from_array(out)
}

///|
test "the seed derives the identity the reference implementation derives" {
  assert_eq(identity().public().code(), published)
  assert_eq(@hex.encode(identity().key()), scalar_hex)
}

///|
test "a written recipient reads back to itself" {
  let recipient = @p256tag.Recipient::of(published) catch {
    error => fail("the published recipient does not parse: \{error}")
  }
  assert_eq(recipient.code(), published)
  assert_eq(recipient.key().length(), @p256tag.point_size)
  assert_eq(identity().public().code(), recipient.code())
}

///|
test "the tag of a known encapsulation is the one the reference computes" {
  let recipient = @p256tag.Recipient::of(published) catch { _ => abort("no") }
  assert_eq(@hex.encode(recipient.tag(encapsulation())), "9ca6bcf6")
}

///|
test "a file sealed to a tagged recipient opens for it" {
  let reader = identity()
  let recipients : Array[&@spec.Recipient] = [reader.public()]
  let file = @moonseal.seal(
    recipients,
    b"for the key on the desk",
    random=pool(),
  ) catch {
    error => fail("cannot seal: \{error}")
  }
  let readers : Array[&@spec.Identity] = [reader]
  assert_eq(@moonseal.open(readers, file), b"for the key on the desk")
}

///|
test "a file addressed to another tagged key does not open" {
  let theirs = @p256tag.Identity::generate(random=pool()) catch {
    _ => abort("no randomness")
  }
  let recipients : Array[&@spec.Recipient] = [theirs.public()]
  let file = @moonseal.seal(recipients, b"not for me", random=pool()) catch {
    _ => abort("cannot seal")
  }
  let readers : Array[&@spec.Identity] = [identity()]
  let refused = try {
    ignore(@moonseal.open(readers, file))
    false
  } catch {
    @spec.Refused::NoMatch => true
    _ => false
  }
  assert_true(refused)
}

///|
test "a tagged stanza carries the tag and the point, in that order" {
  let reader = identity()
  let recipients : Array[&@spec.Recipient] = [reader.public()]
  let file = @moonseal.seal(recipients, b"x", random=pool()) catch {
    _ => abort("cannot seal")
  }
  let (head, _) = @header.Header::decode(file) catch { _ => abort("no header") }
  let stanza = head.stanzas()[0]
  assert_eq(stanza.kind, "p256tag")
  assert_eq(stanza.args.length(), 2)
  let tag = @base64.decode(stanza.args[0], padding=false, strict=true) catch {
    _ => abort("no tag")
  }
  assert_eq(tag.length(), 4)
  let enc = @base64.decode(stanza.args[1], padding=false, strict=true) catch {
    _ => abort("no point")
  }
  assert_eq(enc.length(), 65)
  assert_eq(stanza.body.length(), 32)
}

///|
test "a malformed tagged stanza is a refusal, not somebody else's" {
  let reader = identity()
  let cases : Array[@spec.Stanza] = [
    @spec.Stanza::new(kind="p256tag", args=[], body=Bytes::make(32, 0)),
    @spec.Stanza::new(kind="p256tag", args=["AAAA"], body=Bytes::make(32, 0)),
    @spec.Stanza::new(
      kind="p256tag",
      args=["AAAA", "AAAA"],
      body=Bytes::make(32, 0),
    ),
    @spec.Stanza::new(
      kind="p256tag",
      args=["AAAA", @base64.encode(encapsulation(), padding=false)],
      body=Bytes::make(33, 0),
    ),
  ]
  for stanza in cases {
    let refused = try {
      ignore(reader.unwrap(stanza~))
      false
    } catch {
      @spec.Refused::Stanza(..) => true
      _ => false
    }
    assert_true(refused)
  }
}

///|
test "a stanza of another type is not this identity's" {
  let stanza = @spec.Stanza::new(
    kind="X25519",
    args=["AAAA"],
    body=Bytes::make(32, 0),
  )
  assert_eq(identity().unwrap(stanza~) is None, true)
}

///|
test "a tag that names another key is passed over without the key being used" {
  let other = @p256tag.Identity::generate(random=pool()) catch {
    _ => abort("no randomness")
  }
  let stanza = @spec.Stanza::new(
    kind="p256tag",
    args=[
      @base64.encode(other.public().tag(encapsulation()), padding=false),
      @base64.encode(encapsulation(), padding=false),
    ],
    body=Bytes::make(32, 0),
  )
  assert_eq(identity().unwrap(stanza~) is None, true)
}

///|
test "a point that is not on the curve is refused as a recipient" {
  // A compression byte that means nothing, a point written uncompressed where
  // the format wants it compressed, and a coordinate at the field's modulus.
  let points : Array[Bytes] = [
    Bytes::make(33, 0),
    b"\x04".add(Bytes::make(32, 0)),
    b"\x02".add(
      b"\xff\xff\xff\xff\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
    ),
  ]
  for point in points {
    let refused = try {
      ignore(@p256tag.Recipient::new(point[:]))
      false
    } catch {
      @spec.Refused::Stanza(..) | @spec.Refused::Key(..) => true
      _ => false
    }
    assert_true(refused)
  }
}

///|
test "a written recipient of the wrong kind is refused" {
  let texts : Array[String] = [
    "age1pq1x34nzsvr0rxjsgdn8zgyhfe8j7ceq5r9rdelkjuh3y235jzxshfg87pzf", "age1tag1qwe0kafsjrar4txm6heqnhpfuggzr0gvznz7fvygxrlq90u5mq2pysxtw6j",
    "p256tag1qwe0kafsjrar4txm6heqnhpfuggzr0gvznz7fvygxrlq90u5m",
  ]
  for text in texts {
    let refused = try {
      ignore(@p256tag.Recipient::of(text))
      false
    } catch {
      @spec.Refused::Stanza(..) => true
      _ => false
    }
    assert_true(refused)
  }
}

///|
test "a scalar of the wrong size is refused" {
  let refused = try {
    ignore(@p256tag.Identity::new(Bytes::make(31, 1)))
    false
  } catch {
    @spec.Refused::Key(..) => true
    _ => false
  }
  assert_true(refused)
}
