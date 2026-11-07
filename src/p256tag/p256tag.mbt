// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// How long a public key is as it travels: a P-256 point in the compressed SEC 1
/// form, one byte of parity and thirty-two bytes of coordinate.
pub let point_size : Int32 = 33

///|
/// How long a secret key is: a P-256 scalar, in [1, n).
pub let size : Int32 = 32

///|
/// What this recipient type calls itself in the header.
let kind : String = "p256tag"

///|
/// The string the format uses twice: as the HPKE `info`, and as the salt of the
/// tag. Two different jobs that happen to be spelled the same way, which is why
/// it is one constant here rather than two that could drift apart.
let label : Bytes = b"age-encryption.org/p256tag"

///|
/// The prefix a public key is written with.
let hrp : String = "age1tag"

///|
/// A public key: a P-256 point, and the ability to seal a file key to it.
///
/// Both SEC 1 forms are kept: the compressed one, because that is what the
/// format writes and what the tag hashes, and the uncompressed one, because that
/// is what HPKE hashes into its key schedule. A recipient is read once and used
/// once per file, so the change of shape happens at the door rather than in the
/// middle of sealing.
pub struct Recipient {
  priv key : Bytes
  priv point : Bytes
}

///|
/// From the thirty-three bytes of a compressed point.
///
/// A point that is not on the curve is refused here rather than at sealing time:
/// a recipient is a name for a device, and a name that addresses nothing should
/// not survive being read.
pub fn Recipient::new(point : BytesView) -> Self raise @spec.Refused {
  if point.length() != point_size {
    raise @spec.Refused::Key(want=point_size, got=point.length())
  }
  { key: point.to_owned(), point: @hpke.p256_uncompressed(point), }
}

///|
/// From its written form, `age1tag1…`.
pub fn Recipient::of(text : StringView) -> Self raise @spec.Refused {
  Recipient::new(
    @spec.text_key(text, hrp~, what="a key that starts with age1tag1"),
  )
}

///|
/// The written form, `age1tag1…`.
pub fn Recipient::code(self : Recipient) -> String {
  @keytext.encode(hrp, self.key(), kind=Bech32)
}

///|
/// The raw key, for comparing one recipient with another: the point compressed,
/// which is what the bech32 string carries.
pub fn Recipient::key(self : Recipient) -> BytesView {
  self.key
}

///|
/// The four-byte tag that names this key in a stanza, for the encapsulation the
/// sender drew.
///
/// Exposed because a device that holds the key can compute it too: a hardware
/// key that answers only when asked is asked once per stanza, and the tag is
/// what lets it answer "not mine" without unwrapping anything.
pub fn Recipient::tag(self : Recipient, enc : BytesView) -> Bytes {
  @tag.compute(self.key(), enc, label~)
}

///|
/// A point in the compressed form the format writes: the parity of the second
/// coordinate, then the first.
fn compress(point : BytesView) -> Bytes {
  let out = @buffer.Buffer(size_hint=point_size)
  let odd = (point[64].to_int() & 1) == 1
  out.write_byte(if odd { b'\x03' } else { b'\x02' })
  out.write_bytes(point.clamped_view(start=1, end=33))
  out.to_bytes()
}

///|
/// The encrypting side: one encapsulation, its tag, and the file key sealed
/// under the secret it produced.
pub impl @spec.Recipient for Recipient with fn wrap(self, file_key~, random~) {
  let sent = @hpke.encapsulate(@hpke.P256, self.point[:], random)
  @spec.Stanza::new(
    kind~,
    args=[
      @base64.encode(self.tag(sent.enc), padding=false),
      @base64.encode(sent.enc, padding=false),
    ],
    body=@hpke.seal(@hpke.P256, sent.shared, label, file_key),
  )
}

///|
pub extend Recipient with @spec.Recipient::{wrap}

///|
/// A secret key: the scalar a device would hold, and nothing else.
///
/// The format defines no written form for these — a tagged recipient is the
/// public half of something that lives in hardware — so there is no `code` and
/// no `of`. Where the scalar is kept, and how it is named, are the plugin's
/// business; this type is the arithmetic.
pub struct Identity {
  priv scalar : Bytes
}

///|
/// From thirty-two bytes of scalar.
pub fn Identity::new(scalar : BytesView) -> Self raise @spec.Refused {
  if scalar.length() != size {
    raise @spec.Refused::Key(want=size, got=scalar.length())
  }
  { scalar: scalar.to_owned(), }
}

///|
/// A new scalar, drawn from `random`.
pub fn Identity::generate(
  random~ : &@moonseed.Source,
) -> Self raise @spec.Refused {
  { scalar: @hpke.p256_scalar(random), }
}

///|
/// A scalar derived from a seed, by HPKE's `DeriveKeyPair`.
///
/// Nothing here needs it — a device has a key already — but two implementations
/// that each hold a seed need to agree on the key it stands for, and this is the
/// derivation HPKE defines for exactly that.
pub fn Identity::from_seed(seed : BytesView) -> Self raise @spec.Refused {
  { scalar: @hpke.from_seed(@hpke.P256, seed), }
}

///|
/// The raw scalar, for handing to whatever does keep it.
pub fn Identity::key(self : Identity) -> BytesView {
  self.scalar
}

///|
/// The public half, which is what a sender needs.
pub fn Identity::public(self : Identity) -> Recipient {
  let point = @hpke.public_of(@hpke.P256, self.scalar[:]) catch {
    _ => abort("p256tag: a scalar in [1, n) always has a point")
  }
  { key: compress(point), point, }
}

///|
/// The decrypting side.
///
/// The shape of the stanza is settled before the key is used: a tag that is not
/// four bytes, an encapsulation that is not sixty-five, a body that is not
/// thirty-two are all refusals, while a well-formed stanza whose tag names
/// another device is simply not this identity's.
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
  guard enc.length() == @hpke.enc_size(@hpke.P256) else {
    raise @spec.Refused::Stanza(want="a 65-byte encapsulation")
  }
  guard stanza.body.length() == 32 else {
    raise @spec.Refused::Stanza(want="a 32-byte body")
  }
  if !@crypt.eq(tag, self.public().tag(enc)) {
    return None
  }
  let shared = @hpke.decapsulate(@hpke.P256, self.scalar[:], enc)
  return @hpke.open(@hpke.P256, shared, label, stanza.body[:])
}

///|
pub extend Identity with @spec.Identity::{unwrap}
