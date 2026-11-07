// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// How long a seed is. One thirty-two-byte seed is the whole of a secret: the
/// ML-KEM key and the X25519 scalar are both expanded from it.
pub let size : Int32 = 32

///|
/// What this recipient type calls itself in the header.
let kind : String = "mlkem768x25519"

///|
/// The context string HPKE is keyed with, which keeps a ciphertext made here
/// from being read under some other use of the same KEM.
let info : Bytes = b"age-encryption.org/mlkem768x25519"

///|
/// The prefixes a public key and a secret key are written with.
let recipient_hrp : String = "age1pq"

///|
let identity_hrp : String = "age-secret-key-pq-"

///|
/// A public key: an ML-KEM-768 encapsulation key and an X25519 public key, as
/// the one 1216-byte string the hybrid KEM takes.
pub struct Recipient {
  priv key : Bytes
}

///|
/// From the 1216 bytes of a public key.
pub fn Recipient::new(key : BytesView) -> Self raise @spec.Refused {
  if key.length() != @hpke.public_size(@hpke.XWing) {
    raise @spec.Refused::Key(
      want=@hpke.public_size(@hpke.XWing),
      got=key.length(),
    )
  }
  { key: key.to_owned(), }
}

///|
/// From its written form, `age1pq1…`.
pub fn Recipient::of(text : StringView) -> Self raise @spec.Refused {
  Recipient::new(
    @spec.text_key(
      text,
      hrp=recipient_hrp,
      what="a key that starts with age1pq1",
    ),
  )
}

///|
/// The written form, `age1pq1…`.
pub fn Recipient::code(self : Recipient) -> String {
  @keytext.encode(recipient_hrp, self.key, kind=Bech32)
}

///|
/// The raw key, for comparing one recipient with another.
pub fn Recipient::key(self : Recipient) -> BytesView {
  self.key
}

///|
/// The encrypting side: one encapsulation, and the file key sealed under the
/// secret it produced.
pub impl @spec.Recipient for Recipient with fn wrap(self, file_key~, random~) {
  let sent = @hpke.encapsulate(@hpke.XWing, self.key[:], random)
  @spec.Stanza::new(
    kind~,
    args=[@base64.encode(sent.enc, padding=false)],
    body=@hpke.seal(@hpke.XWing, sent.shared, info, file_key),
  )
}

///|
pub extend Recipient with @spec.Recipient::{wrap}

///|
/// A secret key: the seed both halves are expanded from.
pub struct Identity {
  priv seed : Bytes
}

///|
/// A new seed, drawn from `random`.
pub fn Identity::generate(
  random~ : &@moonseed.Source,
) -> Self raise @spec.Refused {
  { seed: @spec.draw(random, size), }
}

///|
/// From thirty-two bytes of seed.
pub fn Identity::new(seed : BytesView) -> Self raise @spec.Refused {
  if seed.length() != size {
    raise @spec.Refused::Key(want=size, got=seed.length())
  }
  { seed: seed.to_owned(), }
}

///|
/// From its written form, `AGE-SECRET-KEY-PQ-1…`.
pub fn Identity::of(text : StringView) -> Self raise @spec.Refused {
  Identity::new(
    @spec.text_key(
      text,
      hrp=identity_hrp,
      what="a key that starts with AGE-SECRET-KEY-PQ-1",
    ),
  )
}

///|
/// The written form, uppercase so that it is hard to mistake for a public key.
pub fn Identity::code(self : Identity) -> String {
  @keytext.encode(identity_hrp, self.seed, kind=Bech32).to_upper()
}

///|
/// The public half, which is what a sender needs.
pub fn Identity::public(self : Identity) -> Recipient {
  {
    key: @hpke.public_of(@hpke.XWing, self.seed[:]) catch {
      _ => abort("mlkem768x25519: a 32-byte seed always has a public key")
    },
  }
}

///|
/// The decrypting side.
///
/// The checks come before the KEM does: a stanza that is the wrong size is
/// refused without a decapsulation, because the time an answer takes is itself
/// an answer to whoever asked.
pub impl @spec.Identity for Identity with fn unwrap(self, stanza~) {
  if stanza.kind != kind {
    return None
  }
  guard stanza.args.length() == 1 else {
    raise @spec.Refused::Stanza(want="one argument: the encapsulation")
  }
  let enc = @base64.decode(stanza.args[0], padding=false, strict=true) catch {
    _ => raise @spec.Refused::Stanza(want="a base64 encapsulation")
  }
  guard enc.length() == @hpke.enc_size(@hpke.XWing) else {
    raise @spec.Refused::Stanza(want="a 1120-byte encapsulation")
  }
  guard stanza.body.length() == 32 else {
    raise @spec.Refused::Stanza(want="a 32-byte body")
  }
  let shared = @hpke.decapsulate(@hpke.XWing, self.seed[:], enc)
  return @hpke.open(@hpke.XWing, shared, info, stanza.body[:])
}

///|
pub extend Identity with @spec.Identity::{unwrap}
