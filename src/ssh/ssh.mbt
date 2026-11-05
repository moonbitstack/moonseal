// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// What an Ed25519 stanza calls itself, and the context both derivations use.
let ed25519_kind : String = "ssh-ed25519"

///|
let rsa_kind : String = "ssh-rsa"

///|
let ed25519_label : Bytes = b"age-encryption.org/v1/ssh-ed25519"

///|
/// The OAEP label of the RSA type, which is also what keeps an OAEP message made
/// for something else from being read as a wrapped file key.
let rsa_label : Bytes = b"age-encryption.org/v1/ssh-rsa"

///|
/// The smallest RSA key this library will address a file to. Below it the
/// modulus is what an attacker with a laptop can factor, and a stanza that
/// claims one is a file that looks safer than it is.
pub let min_rsa_bits : Int32 = 2048

///|
/// What a recipient key actually does when a file key is wrapped.
priv enum Target {
  Ed25519(montgomery~ : Bytes)
  Rsa(key~ : @rsa.PublicKey, modulus~ : Bytes)
}

///|
/// A public key, as the thing you seal to.
pub struct Recipient {
  priv kind : String
  priv blob : Bytes
  priv target : Target
}

///|
/// From the key as SSH writes it: the type name, then the type's fields, all
/// length-prefixed.
///
/// A key of a type this library does not implement is refused rather than
/// carried: a recipient type has to wrap a file key, and there is nothing to
/// call for a key that only signs.
pub fn Recipient::new(blob : BytesView) -> Self raise @spec.Refused {
  let wire = Wire::new(blob)
  let kind = wire.text()
  if kind == ed25519_kind {
    let public = wire.string()
    guard public.length() == 32 else {
      raise @spec.Refused::Stanza(want="a 32-byte Ed25519 public key")
    }
    guard wire.left() == 0 else {
      raise @spec.Refused::Stanza(want="nothing after an Ed25519 key")
    }
    return {
      kind,
      blob: blob.to_owned(),
      target: Target::Ed25519(montgomery=montgomery(public)),
    }
  }
  if kind != rsa_kind {
    raise @spec.Refused::Stanza(want="an ssh-ed25519 or ssh-rsa public key")
  }
  let exponent = wire.mpint()
  let modulus = wire.mpint()
  guard wire.left() == 0 else {
    raise @spec.Refused::Stanza(want="nothing after an RSA key")
  }
  if bits(modulus) < min_rsa_bits {
    raise @spec.Refused::Stanza(want="an RSA key of at least 2048 bits")
  }
  let key = @rsa.PublicKey::new(modulus, exponent) catch {
    _ => raise @spec.Refused::Stanza(want="an RSA public key")
  }
  { kind, blob: blob.to_owned(), target: Target::Rsa(key~, modulus~), }
}

///|
/// From an `authorized_keys` line: options first if there are any, then the type,
/// then the base64 key, then a comment that is not read.
pub fn Recipient::of(text : StringView) -> Self raise @spec.Refused {
  let words = words_of(text)
  let mut at = 0
  while at + 1 < words.length() {
    let kind = words[at]
    if kind == ed25519_kind || kind == rsa_kind {
      let blob = @base64.decode(words[at + 1], padding=false, strict=true) catch {
        _ => raise @spec.Refused::Stanza(want="a base64 SSH public key")
      }
      let recipient = Recipient::new(blob)
      if recipient.kind != kind {
        raise @spec.Refused::Stanza(want="a key of the type the line names")
      }
      return recipient
    }
    at = at + 1
  }
  raise @spec.Refused::Stanza(want="an ssh-ed25519 or ssh-rsa public key")
}

///|
/// The written form, which is what an `authorized_keys` line holds after its
/// options: the type, a space, and the key.
pub fn Recipient::code(self : Recipient) -> String {
  self.kind + " " + @base64.encode(self.blob, padding=false)
}

///|
/// The four-byte tag that names this key in a stanza.
pub fn Recipient::fingerprint(self : Recipient) -> String {
  tag_of(self.blob)
}

///|
/// Which kind of SSH key this is.
///
/// ```mbt check
/// test {
///   assert_eq(
///     @ssh.Recipient::of(
///       "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
///     ).kind(),
///     "ssh-ed25519",
///   )
/// }
/// ```
pub fn Recipient::kind(self : Recipient) -> String {
  self.kind
}

///|
/// The key as SSH writes it, for comparing one recipient with another.
pub fn Recipient::blob(self : Recipient) -> BytesView {
  self.blob
}

///|
/// The encrypting side.
pub impl @spec.Recipient for Recipient with fn wrap(self, file_key~, random~) {
  match self.target {
    Ed25519(montgomery~) =>
      ed25519_wrap(self.blob, montgomery, file_key, random)
    Rsa(key~, modulus~) => rsa_wrap(self.blob, key, modulus, file_key, random)
  }
}

///|
pub extend Recipient with @spec.Recipient::{wrap}

///|
/// A secret key, and the public half it was read from.
priv enum Secret {
  Ed25519(scalar~ : Bytes, montgomery~ : Bytes)
  Rsa(key~ : @rsa.PrivateKey, modulus~ : Bytes)
}

///|
/// A secret key, as the thing that opens a file.
pub struct Identity {
  priv kind : String
  priv blob : Bytes
  priv secret : Secret
}

///|
/// The public half, which is what a sender needs. It is rebuilt from the secret
/// rather than read back out of the file it came from, so that a key and the
/// recipient it names cannot disagree.
pub fn Identity::public(self : Identity) -> Recipient {
  let target = match self.secret {
    Ed25519(montgomery~, ..) => Target::Ed25519(montgomery~)
    Rsa(key~, modulus~) => Target::Rsa(key=key.public(), modulus~)
  }
  { kind: self.kind, blob: self.blob, target, }
}

///|
/// Which kind of SSH key this is.
pub fn Identity::kind(self : Identity) -> String {
  self.kind
}

///|
/// The public key as SSH writes it, which is what a stanza's tag hashes.
pub fn Identity::blob(self : Identity) -> BytesView {
  self.blob
}

///|
/// The decrypting side.
pub impl @spec.Identity for Identity with fn unwrap(self, stanza~) {
  if stanza.kind != self.kind {
    return None
  }
  match self.secret {
    Ed25519(scalar~, montgomery~) =>
      ed25519_unwrap(self.blob, scalar, montgomery, stanza)
    Rsa(key~, ..) => rsa_unwrap(self.blob, key, stanza)
  }
}

///|
pub extend Identity with @spec.Identity::{unwrap}

///|
/// The twelve zero bytes the wrap key is used with. The key is fresh for every
/// stanza, so a nonce that never varies is not a nonce being reused.
fn zeros() -> Bytes {
  Bytes::make(12, 0)
}

///|
/// The tweak that turns the X25519 secret into one only this SSH key can use.
///
/// Without it, the same X25519 key would be reachable through an Ed25519 key
/// that happens to share its scalar, and an SSH key would be a weaker alias for
/// an age one. The tweak is derived from the public key, so both sides can
/// compute it and neither has to store it.
fn tweak(blob : BytesView) -> Bytes {
  @crypt.hkdf(b""[:], blob, ed25519_label, len=32)
}

///|
/// An X25519 public key, or the reason a scalar has none.
fn public_of(scalar : BytesView) -> Bytes raise @spec.Refused {
  match @crypt.x25519_public(scalar) {
    Some(public) => public
    None => raise @spec.Refused::Stanza(want="an X25519 scalar")
  }
}

///|
fn shared_of(
  scalar : BytesView,
  point : BytesView,
) -> Bytes raise @spec.Refused {
  match @crypt.x25519_shared(scalar, point) {
    Some(shared) => shared
    None => raise @spec.Refused::Stanza(want="a share that is not low-order")
  }
}

///|
/// One Ed25519 stanza: an ephemeral X25519 share, and the file key under the
/// key both sides derive from it.
fn ed25519_wrap(
  blob : BytesView,
  montgomery : BytesView,
  file_key : BytesView,
  random : &@moonseed.Source,
) -> @spec.Stanza raise @spec.Refused {
  let ephemeral = @spec.draw(random, 32)
  let share = public_of(ephemeral)
  let shared = shared_of(ephemeral, montgomery)
  let tweaked = shared_of(tweak(blob), shared)
  let key = @crypt.hkdf(
    tweaked,
    share.add(montgomery.to_owned()),
    ed25519_label,
    len=32,
  )
  @spec.Stanza::new(
    kind=ed25519_kind,
    args=[tag_of(blob), @base64.encode(share, padding=false)],
    body=@crypt.seal(key, zeros(), file_key),
  )
}

///|
fn ed25519_unwrap(
  blob : BytesView,
  scalar : BytesView,
  montgomery : BytesView,
  stanza : @spec.Stanza,
) -> Bytes? raise @spec.Refused {
  guard stanza.args.length() == 2 else {
    raise @spec.Refused::Stanza(want="two arguments: the tag and the share")
  }
  guard stanza.body.length() == 32 else {
    raise @spec.Refused::Stanza(want="a 32-byte body")
  }
  // The tag is a hint that costs four bytes, and a mismatch means the file was
  // addressed to a key that is not this one — which is not an error.
  if stanza.args[0] != tag_of(blob) {
    return None
  }
  let share = @base64.decode(stanza.args[1], padding=false, strict=true) catch {
    _ => raise @spec.Refused::Stanza(want="a base64 share")
  }
  guard share.length() == 32 else {
    raise @spec.Refused::Stanza(want="a 32-byte share")
  }
  let shared = shared_of(scalar, share)
  let tweaked = shared_of(tweak(blob), shared)
  let key = @crypt.hkdf(
    tweaked,
    share.add(montgomery.to_owned()),
    ed25519_label,
    len=32,
  )
  return @crypt.open(key, zeros(), stanza.body[:])
}

///|
/// One RSA stanza: the file key under RSA-OAEP, with the tag as its only
/// argument.
fn rsa_wrap(
  blob : BytesView,
  key : @rsa.PublicKey,
  modulus : BytesView,
  file_key : BytesView,
  random : &@moonseed.Source,
) -> @spec.Stanza raise @spec.Refused {
  if bits(modulus) < min_rsa_bits {
    raise @spec.Refused::Stanza(want="an RSA key of at least 2048 bits")
  }
  // OAEP derives its mask from a seed the length of the hash; the caller's
  // source is where it comes from, like every other drawn value in a file.
  let seed = @spec.draw(random, 32)
  let body = key.encrypt(file_key, seed~, digest=@rsa.Sha256, label=rsa_label) catch {
    _ => raise @spec.Refused::Stanza(want="an RSA key that can wrap a file key")
  }
  @spec.Stanza::new(kind=rsa_kind, args=[tag_of(blob)], body~)
}

///|
fn rsa_unwrap(
  blob : BytesView,
  key : @rsa.PrivateKey,
  stanza : @spec.Stanza,
) -> Bytes? raise @spec.Refused {
  guard stanza.args.length() == 1 else {
    raise @spec.Refused::Stanza(want="one argument: the tag")
  }
  if stanza.args[0] != tag_of(blob) {
    return None
  }
  if stanza.body.length() != key.size() {
    return None
  }
  return Some(
    key.decrypt(stanza.body[:], digest=@rsa.Sha256, label=rsa_label) catch {
      _ => return None
    },
  )
}
