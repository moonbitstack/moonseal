// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// One of the two files, as bytes.
fn file(text : String) -> Bytes raise @spec.Refused {
  @base64.decode(text, padding=true, strict=true) catch {
    _ => raise @spec.Refused::Header(at=0, want="a base64 file")
  }
}

///|
/// The identity the reference implementation's test plugin holds, in each of the
/// two tagged types.
fn readers() -> (Array[&@spec.Identity], Array[&@spec.Identity]) {
  let classic : Array[&@spec.Identity] = []
  let hybrid : Array[&@spec.Identity] = []
  let scalar = @p256tag.Identity::from_seed(b"age-plugin-tagtest") catch {
    error => abort("the tagged identity does not derive: \{error}")
  }
  classic.push(scalar)
  let seed = @mlkem768p256tag.Identity::from_seed(b"age-plugin-tagtest") catch {
    error => abort("the hybrid tagged identity does not derive: \{error}")
  }
  hybrid.push(seed)
  (classic, hybrid)
}

///|
/// Randomness that is the same every time.
fn pool() -> @moonseed.Replay {
  @moonseed.Replay::new(
    Bytes::from_array(
      Array::makei(512, fn(i) { ((i * 37 + 11) % 256).to_byte() }),
    ),
  )
}

///|
test "interop: a tagged file age sealed opens here" {
  let (classic, _) = readers()
  let plain = @moonseal.open(classic, file(@tagged.classic)) catch {
    error => fail("age's tagged file does not open: \{error}")
  }
  assert_eq(@hex.encode(@sha2.hash(plain)), @tagged.digest)
  assert_eq(plain, @tagged.plain)
}

///|
test "interop: a hybrid tagged file age sealed opens here" {
  let (_, hybrid) = readers()
  let plain = @moonseal.open(hybrid, file(@tagged.hybrid)) catch {
    error => fail("age's hybrid tagged file does not open: \{error}")
  }
  assert_eq(@hex.encode(@sha2.hash(plain)), @tagged.digest)
  assert_eq(plain, @tagged.plain)
}

///|
test "interop: the wrong tagged identity opens neither file" {
  let other = @p256tag.Identity::generate(random=pool()) catch {
    _ => abort("no randomness")
  }
  let readers : Array[&@spec.Identity] = [other]
  let refused = try {
    ignore(@moonseal.open(readers, file(@tagged.classic)))
    false
  } catch {
    @spec.Refused::NoMatch => true
    _ => false
  }
  assert_true(refused)
}

///|
test "a file addressed to both tagged types opens with either" {
  let (classic, hybrid) = readers()
  let first = @p256tag.Identity::from_seed(b"age-plugin-tagtest") catch {
    _ => abort("no identity")
  }
  let second = @mlkem768p256tag.Identity::from_seed(b"age-plugin-tagtest") catch {
    _ => abort("no identity")
  }
  let recipients : Array[&@spec.Recipient] = [first.public(), second.public()]
  let written = @moonseal.seal(
    recipients,
    b"two kinds of device",
    random=pool(),
  ) catch {
    error => fail("cannot seal: \{error}")
  }
  assert_eq(@moonseal.open(classic, written), b"two kinds of device")
  assert_eq(@moonseal.open(hybrid, written), b"two kinds of device")
}
