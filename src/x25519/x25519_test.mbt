// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The identity the published vectors use, which is the one string that has to
/// parse exactly as it always has.
let known : String = "AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM0"

///|
test "a secret key round trips through its written form" {
  let identity = @x25519.Identity::of(known) catch {
    error => fail("cannot read the published identity: \{error}")
  }
  assert_eq(identity.code(), known)
  // The public half is a bech32 string with its own prefix, and it comes back.
  let public = identity.public().code()
  assert_true(public.has_prefix("age1"))
  let back = @x25519.Recipient::of(public) catch {
    error => fail("cannot read back a public key we wrote: \{error}")
  }
  assert_eq(back.code(), public)
  assert_eq(back.key(), identity.public().key())
}

///|
test "a key that is nearly a key is refused" {
  let cases = [
    // The wrong prefix: a public key where a secret one belongs.
    "age1gtejpc0gyrfvz0q7vap0x2n4ecvhehw4a33zq0dz2qpy57z9yq5q6cqv7y",
    // One character changed, so the checksum does not hold.
     "AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM1",
    // Right shape, wrong length.
     "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ",
    // Not bech32 at all.
     "hello",
  ]
  for case in cases {
    let refused = try {
      ignore(@x25519.Identity::of(case))
      false
    } catch {
      @spec.Refused::Stanza(..) => true
      _ => false
    }
    assert_true(refused, msg="accepted: " + case)
  }
}

///|
test "a stanza wraps the file key for its own key and no other" {
  let mine = @x25519.Identity::of(known) catch { _ => abort("no") }
  let other = @x25519.Identity::new(Bytes::make(32, 0x77)) catch {
    _ => abort("no")
  }
  let random = @moonrand.Replay::new(Bytes::make(64, 0x08))
  let file_key = Bytes::make(16, 0x09)
  let stanza = mine.public().wrap(file_key~, random~) catch {
      error => fail("cannot wrap: \{error}")
    }
  assert_eq(stanza.kind, "X25519")
  assert_eq(stanza.args.length(), 1)
  assert_eq(stanza.body.length(), 32)
  assert_eq(mine.unwrap(stanza~), Some(file_key))
  assert_eq(other.unwrap(stanza~), None)
}

///|
/// A share of a low order point would make the shared secret the same for
/// everybody, so a stanza that carries one is refused rather than tried.
test "a share that is a low order point is refused" {
  let mine = @x25519.Identity::of(known) catch { _ => abort("no") }
  let stanza = @spec.Stanza::new(
    kind="X25519",
    args=[@base64.encode(Bytes::make(32, 0), padding=false)],
    body=Bytes::make(32, 0),
  )
  let refused = try {
    ignore(mine.unwrap(stanza~))
    false
  } catch {
    @spec.Refused::Stanza(..) => true
    _ => false
  }
  assert_true(refused)
}

///|
test "a stanza of another type is not this identity's" {
  let mine = @x25519.Identity::of(known) catch { _ => abort("no") }
  let stanza = @spec.Stanza::new(
    kind="scrypt",
    args=[],
    body=Bytes::make(32, 0),
  )
  assert_eq(mine.unwrap(stanza~), None)
}

///|
test "a body of the wrong size is refused before it is decrypted" {
  let mine = @x25519.Identity::of(known) catch { _ => abort("no") }
  let stanza = @spec.Stanza::new(
    kind="X25519",
    args=[@base64.encode(Bytes::make(32, 1), padding=false)],
    body=Bytes::make(48, 0),
  )
  let refused = try {
    ignore(mine.unwrap(stanza~))
    false
  } catch {
    @spec.Refused::Stanza(..) => true
    _ => false
  }
  assert_true(refused)
}
