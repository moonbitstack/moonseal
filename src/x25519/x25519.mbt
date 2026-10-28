// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// How long a public key, a secret key and a share are. X25519 has no other
/// size.
pub let size : Int32 = 32

///|
/// What an X25519 stanza calls itself, and the context string the wrap key is
/// derived under.
let kind : String = "X25519"

///|
let context : Bytes = b"age-encryption.org/v1/X25519"

///|
/// The prefix a public key is written with, and the one a secret key is.
let recipient_hrp : String = "age"

///|
let identity_hrp : String = "AGE-SECRET-KEY-"

///|
/// A public key, as the thing you seal to.
pub struct Recipient {
  priv key : Bytes
}

///|
/// From thirty-two bytes of public key.
pub fn Recipient::new(key : BytesView) -> Self raise @spec.Refused {
  if key.length() != size {
    raise @spec.Refused::Stanza(want="a 32-byte X25519 public key")
  }
  { key: key.to_owned(), }
}

///|
/// From its written form, `age1…`. The case of the string carries no meaning:
/// bech32 allows either, and the checksum is taken over the lowercase one.
pub fn Recipient::of(text : StringView) -> Self raise @spec.Refused {
  let (hrp, data, variant) = @bech32.decode_bytes(text) catch {
    _ => raise @spec.Refused::Stanza(want="a bech32 public key")
  }
  if hrp != recipient_hrp {
    raise @spec.Refused::Stanza(want="a key that starts with age1")
  }
  if variant != @bech32.Bech32 {
    raise @spec.Refused::Stanza(want="a bech32 checksum, not bech32m")
  }
  Recipient::new(data)
}

///|
/// The written form, `age1…`.
pub fn Recipient::code(self : Recipient) -> String {
  @bech32.encode(recipient_hrp, self.key, variant=@bech32.Bech32) catch {
    _ => abort("x25519: a 32-byte key always encodes")
  }
}

///|
/// The raw key, for comparing one recipient with another.
pub fn Recipient::key(self : Recipient) -> BytesView {
  self.key
}

///|
/// The encrypting side: an ephemeral secret, a share, and one wrapped file key.
pub impl @spec.Recipient for Recipient with fn wrap(self, file_key~, entropy~) {
  let secret = entropy.take(len=size)
  let share = match @crypt.x25519_public(secret) {
    Some(share) => share
    None => abort("x25519: a freshly drawn secret is a valid scalar")
  }
  let shared = match @crypt.x25519_shared(secret, self.key[:]) {
    Some(shared) => shared
    None =>
      raise @spec.Refused::Stanza(
        want="a public key that is not a low-order point",
      )
  }
  let key = @crypt.hkdf(shared, share.add(self.key), context, len=32)
  let body = @crypt.seal(key, zeros(), file_key)
  @spec.Stanza::new(kind~, args=[@base64.encode(share)], body~)
}

///|
pub extend Recipient with @spec.Recipient::{wrap}

///|
/// A secret key.
pub struct Identity {
  priv scalar : Bytes
}

///|
/// A new secret key, drawn from the entropy the caller handed in. A secret key is
/// thirty-two random bytes and nothing else; X25519 clamps them when it uses
/// them.
pub fn Identity::generate(entropy~ : @spec.Entropy) -> Self raise @spec.Refused {
  { scalar: entropy.take(len=size).to_owned(), }
}

///|
/// From thirty-two bytes of secret key.
pub fn Identity::new(scalar : BytesView) -> Self raise @spec.Refused {
  if scalar.length() != size {
    raise @spec.Refused::Stanza(want="a 32-byte X25519 secret key")
  }
  { scalar: scalar.to_owned(), }
}

///|
/// From its written form, `AGE-SECRET-KEY-1…`.
pub fn Identity::of(text : StringView) -> Self raise @spec.Refused {
  let (hrp, data, variant) = @bech32.decode_bytes(text) catch {
    _ => raise @spec.Refused::Stanza(want="a bech32 secret key")
  }
  if hrp != "age-secret-key-" {
    raise @spec.Refused::Stanza(want="a key that starts with AGE-SECRET-KEY-1")
  }
  if variant != @bech32.Bech32 {
    raise @spec.Refused::Stanza(want="a bech32 checksum, not bech32m")
  }
  Identity::new(data)
}

///|
/// The written form, `AGE-SECRET-KEY-1…`. Uppercase, which is how bech32 spells a
/// secret so that it is hard to mistake for a public one.
pub fn Identity::code(self : Identity) -> String {
  @bech32.encode(identity_hrp, self.scalar, variant=@bech32.Bech32) catch {
    _ => abort("x25519: a 32-byte key always encodes")
  }
}

///|
/// The public half, which is what a sender needs.
pub fn Identity::public(self : Identity) -> Recipient {
  {
    key: match @crypt.x25519_public(self.scalar[:]) {
      Some(key) => key
      None => abort("x25519: a 32-byte scalar always has a public key")
    },
  }
}

///|
pub extend Identity with @spec.Identity::{unwrap}

///|
/// The decrypting side: every stanza of this type, in turn.
pub impl @spec.Identity for Identity with fn unwrap(self, stanza~) {
  if stanza.kind != kind {
    return None
  }
  guard stanza.args.length() == 1 else {
    raise @spec.Refused::Stanza(want="one argument: the ephemeral share")
  }
  guard stanza.body.length() == 32 else {
    raise @spec.Refused::Stanza(want="a 32-byte body")
  }
  let share = @base64.decode(stanza.args[0]) catch {
    _ => raise @spec.Refused::Stanza(want="a base64 share")
  }
  guard share.length() == size else {
    raise @spec.Refused::Stanza(want="a 32-byte share")
  }
  let shared = match @crypt.x25519_shared(self.scalar[:], share) {
    Some(shared) => shared
    None =>
      raise @spec.Refused::Stanza(want="a share that is not a low-order point")
  }
  let key = @crypt.hkdf(shared, share.add(self.public().key), context, len=32)
  let plain = @crypt.open(key, zeros(), stanza.body[:])
  return plain
}

///|
/// The twelve zero bytes the wrap key is used with. The key is used once, so a
/// nonce that never varies is not a nonce being reused.
fn zeros() -> Bytes {
  Bytes::make(12, 0)
}
