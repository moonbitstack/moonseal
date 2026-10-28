// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The work factor is written into the file, so it is the sender's choice and the
/// reader's limit that meet in the stanza.
test "the work factor is written and read" {
  let entropy = @spec.Entropy::new(Bytes::make(64, 0x21))
  // Fourteen is sixteen mebibytes of scratch space, which is as far as a test
  // that runs on four backends should go: the work factor changes the cost, not
  // the code, and the default of eighteen is the same path with a longer walk.
  for log_n in [10, 12, 14] {
    let stanza = @scrypt.Recipient::new("password", log_n~).wrap(
      file_key=Bytes::make(16, 1),
      entropy~,
    ) catch {
      error => fail("cannot wrap: \{error}")
    }
    assert_eq(stanza.kind, "scrypt")
    assert_eq(stanza.args.length(), 2)
    assert_eq(stanza.args[1], log_n.to_string())
    assert_eq(stanza.body.length(), 32)
    let identity = @scrypt.Identity::new("password")
    assert_eq(identity.unwrap(stanza~), Some(Bytes::make(16, 1)))
  }
}

///|
test "the default work factor is eighteen" {
  assert_eq(@scrypt.Recipient::new("password").log_n(), 18)
  assert_eq(@scrypt.default_log_n, 18)
  assert_eq(@scrypt.max_log_n, 22)
}

///|
/// A reader may refuse a file that asks for more work than it agreed to, and it
/// refuses it as a broken stanza rather than as an unknown one: the file is
/// addressed to it, and it will not run.
test "a work factor above the reader's ceiling is refused" {
  let stanza = @scrypt.Recipient::new("password", log_n=12).wrap(
    file_key=Bytes::make(16, 1),
    entropy=@spec.Entropy::new(Bytes::make(64, 5)),
  ) catch {
    _ => abort("no")
  }
  let modest = @scrypt.Identity::new("password", max_log_n=10)
  let refused = try {
    ignore(modest.unwrap(stanza~))
    false
  } catch {
    @spec.Refused::Stanza(..) => true
    _ => false
  }
  assert_true(refused)
  // The same stanza opens for a reader that accepts it.
  let generous = @scrypt.Identity::new("password", max_log_n=12)
  assert_eq(generous.unwrap(stanza~), Some(Bytes::make(16, 1)))
}

///|
test "the wrong passphrase opens nothing" {
  let stanza = @scrypt.Recipient::new("password", log_n=10).wrap(
    file_key=Bytes::make(16, 1),
    entropy=@spec.Entropy::new(Bytes::make(64, 7)),
  ) catch {
    _ => abort("no")
  }
  let wrong = @scrypt.Identity::new("passphrase")
  assert_eq(wrong.unwrap(stanza~), None)
}

///|
/// The third argument is a decimal without a leading zero, and nothing else is a
/// number: this is where a file can say "2^9999" and be told no.
test "a work factor that is not a plain decimal is refused" {
  let identity = @scrypt.Identity::new("password")
  let cases = ["010", "0", "-1", "1e3", "18x", "", "23", "99999999999999999999"]
  for case in cases {
    let stanza = @spec.Stanza::new(
      kind="scrypt",
      args=[@base64.encode(Bytes::make(16, 0)), case],
      body=Bytes::make(32, 0),
    )
    let refused = try {
      ignore(identity.unwrap(stanza~))
      false
    } catch {
      @spec.Refused::Stanza(..) => true
      _ => false
    }
    assert_true(refused, msg="accepted a work factor of " + case)
  }
}

///|
test "a salt that is not sixteen bytes is refused" {
  let identity = @scrypt.Identity::new("password")
  for size in [0, 8, 15, 17, 32] {
    let stanza = @spec.Stanza::new(
      kind="scrypt",
      args=[@base64.encode(Bytes::make(size, 0)), "10"],
      body=Bytes::make(32, 0),
    )
    let refused = try {
      ignore(identity.unwrap(stanza~))
      false
    } catch {
      @spec.Refused::Stanza(..) => true
      _ => false
    }
    assert_true(refused, msg="accepted a salt of \{size} bytes")
  }
}

///|
test "panic a work factor this library will not run" {
  ignore(@scrypt.Recipient::new("password", log_n=23))
}

///|
test "panic a ceiling this library will not run" {
  ignore(@scrypt.Identity::new("password", max_log_n=40))
}
