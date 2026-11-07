// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// How long a public key is: an ML-KEM-768 encapsulation key with an
/// uncompressed P-256 point behind it, written as one string.
///
/// It is written as a sum because the numbers are FIPS 203's and the curve's,
/// and a reader should be able to check them without a calculator.
pub let public_size : Int32 = 1184 + 65

///|
/// How long a secret key is: one thirty-two-byte seed, from which both halves
/// are expanded.
pub let size : Int32 = 32

///|
/// What this recipient type calls itself in the header.
let kind : String = "mlkem768p256tag"

///|
/// The string the format uses both as the HPKE `info` and as the salt of the
/// tag.
let label : Bytes = b"age-encryption.org/mlkem768p256tag"

///|
/// The prefix a public key is written with.
let hrp : String = "age1tagpq"

///|
/// Where the P-256 point starts in a public key, which is also where the part
/// the tag hashes starts.
let point_at : Int32 = 1184

///|
/// A public key: an ML-KEM-768 encapsulation key and a P-256 point, as one
/// 1249-byte string, which is the shape the hybrid KEM takes.
pub struct Recipient {
  priv key : Bytes
}

///|
/// From the 1249 bytes of a public key.
pub fn Recipient::new(key : BytesView) -> Self raise @spec.Refused {
  if key.length() != public_size {
    raise @spec.Refused::Key(want=public_size, got=key.length())
  }
  // Both halves are checked as they are read: an ML-KEM key whose coefficients
  // are out of range, or a point that is not on the curve, is a name for a
  // device that cannot exist.
  ignore(
    @mlkem.PublicKey::new(kind=@mlkem.K768, key.clamped_view(end=point_at)) catch {
      _ => raise @spec.Refused::Stanza(want="an ML-KEM-768 encapsulation key")
    },
  )
  ignore(@hpke.p256_uncompressed(key.clamped_view(start=point_at)))
  { key: key.to_owned(), }
}

///|
/// From its written form, `age1tagpq1…`.
pub fn Recipient::of(text : StringView) -> Self raise @spec.Refused {
  Recipient::new(
    @spec.text_key(text, hrp~, what="a key that starts with age1tagpq1"),
  )
}

///|
/// The written form, `age1tagpq1…`.
pub fn Recipient::code(self : Recipient) -> String {
  @keytext.encode(hrp, self.key, kind=Bech32)
}

///|
/// The raw key, for comparing one recipient with another.
pub fn Recipient::key(self : Recipient) -> BytesView {
  self.key
}

///|
/// The four-byte tag that names this key in a stanza, for the encapsulation the
/// sender drew.
///
/// Only the P-256 half is hashed. The ML-KEM half may be sealed inside the
/// device, unreadable without it, and a tag that cannot be computed without the
/// device would be no use to the reader that has it.
pub fn Recipient::tag(self : Recipient, enc : BytesView) -> Bytes {
  @tag.compute(self.key.clamped_view(start=point_at), enc, label~)
}

///|
/// The encrypting side: one encapsulation, its tag, and the file key sealed
/// under the secret it produced.
pub impl @spec.Recipient for Recipient with fn wrap(self, file_key~, random~) {
  let sent = @hpke.encapsulate(@hpke.Mlkem768P256, self.key[:], random)
  @spec.Stanza::new(
    kind~,
    args=[
      @base64.encode(self.tag(sent.enc), padding=false),
      @base64.encode(sent.enc, padding=false),
    ],
    body=@hpke.seal(@hpke.Mlkem768P256, sent.shared, label, file_key),
  )
}

///|
pub extend Recipient with @spec.Recipient::{wrap}

///|
/// A secret key: one seed, from which the ML-KEM key and the P-256 scalar are
/// both expanded.
///
/// As with the plain tagged type, the format defines no written form for it. A
/// device that keeps a seed of its own and expands it the way HPKE does has an
/// identity here without inventing an encoding.
pub struct Identity {
  priv seed : Bytes
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
/// A new seed, drawn from `random`.
pub fn Identity::generate(
  random~ : &@moonseed.Source,
) -> Self raise @spec.Refused {
  { seed: @spec.draw(random, size), }
}

///|
/// A seed derived from a caller's bytes, by HPKE's `DeriveKeyPair`.
pub fn Identity::from_seed(seed : BytesView) -> Self raise @spec.Refused {
  { seed: @hpke.from_seed(@hpke.Mlkem768P256, seed), }
}

///|
/// The raw seed, for handing to whatever does keep it.
pub fn Identity::key(self : Identity) -> BytesView {
  self.seed
}

///|
/// The public half, which is what a sender needs.
pub fn Identity::public(self : Identity) -> Recipient {
  {
    key: @hpke.public_of(@hpke.Mlkem768P256, self.seed[:]) catch {
      _ => abort("mlkem768p256tag: a 32-byte seed always has a public key")
    },
  }
}

///|
/// The decrypting side.
///
/// The shape of the stanza is settled before the key is used, and the tag is
/// compared before the KEM runs: a device that has to be asked deserves not to
/// be asked about a file that was never addressed to it.
pub impl @spec.Identity for Identity with fn unwrap(self, stanza~) {
  if stanza.kind != kind {
    return None
  }
  guard stanza.args.length() == 2 else {
    raise @spec.Refused::Stanza(want="two arguments: the tag and the point")
  }
  let tag = @base64.decode(stanza.args[0], padding=false, strict=true) catch {
    _ => raise @spec.Refused::Stanza(want="a base64 tag")
  }
  guard tag.length() == 4 else {
    raise @spec.Refused::Stanza(want="a four-byte tag")
  }
  let enc = @base64.decode(stanza.args[1], padding=false, strict=true) catch {
    _ => raise @spec.Refused::Stanza(want="a base64 encapsulation")
  }
  guard enc.length() == @hpke.enc_size(@hpke.Mlkem768P256) else {
    raise @spec.Refused::Stanza(want="a 1153-byte encapsulation")
  }
  guard stanza.body.length() == 32 else {
    raise @spec.Refused::Stanza(want="a 32-byte body")
  }
  if !@crypt.eq(tag, self.public().tag(enc)) {
    return None
  }
  let shared = @hpke.decapsulate(@hpke.Mlkem768P256, self.seed[:], enc)
  return @hpke.open(@hpke.Mlkem768P256, shared, label, stanza.body[:])
}

///|
pub extend Identity with @spec.Identity::{unwrap}
