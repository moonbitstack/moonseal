// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Why this library would not do what it was asked.
///
/// The variants are the places a file can stop being a file: the header does not
/// say what the format says it says, a stanza of a known type does not either,
/// the MAC over the header does not check out, no identity opened any stanza, a
/// payload chunk did not authenticate, the text was not the armor it claimed to
/// be, the file key that came out of a stanza is not the size this format
/// defines, there was less randomness than the file needs, or an input was
/// longer than this library will read.
///
/// `at` is an offset in bytes from the start of the input the call was given.
pub(all) suberror Refused {
  Header(at~ : Int32, want~ : String)
  Stanza(want~ : String)
  Mac
  NoMatch
  Payload(at~ : Int32)
  Armor(at~ : Int32, want~ : String)
  Key(want~ : Int32, got~ : Int32)
  Entropy(want~ : Int32, got~ : Int32)
  Limit(want~ : Int32, got~ : Int32)
} derive(Eq, Debug)

///|
pub extend Refused with Eq::{equal, not_equal}

///|
pub extend Refused with Show::{to_string, output}

///|
/// What went wrong, in one line, with the offset where there is one. Printing a
/// refusal is what a caller does when it has nobody to hand it to.
pub impl Show for Refused with fn output(self, logger) {
  match self {
    Header(at~, want~) =>
      logger.write_string("not a header at byte \{at}: \{want}")
    Stanza(want~) =>
      logger.write_string("a stanza is not as specified: \{want}")
    Mac => logger.write_string("the header MAC does not verify")
    NoMatch => logger.write_string("no identity opens this file")
    Payload(at~) => logger.write_string("the payload fails at byte \{at}")
    Armor(at~, want~) => logger.write_string("not armor at byte \{at}: \{want}")
    Key(want~, got~) =>
      logger.write_string("a file key of \{want} bytes, not \{got}")
    Entropy(want~, got~) =>
      logger.write_string("\{want} bytes of randomness needed, \{got} left")
    Limit(want~, got~) =>
      logger.write_string("at most \{want} bytes, \{got} given")
  }
}

///|
pub extend Refused with Debug::{to_repr}

///|
/// One recipient stanza: the type, the arguments after it, and the body that
/// carries the file key wrapped for whoever holds the matching secret.
///
/// A recipient type is nothing more than a name, a list of arguments it defines
/// the meaning of, and a body; the header carries them without understanding
/// them, which is what lets a type this library has never heard of travel
/// through it.
pub(all) struct Stanza {
  kind : String
  args : Array[String]
  body : Bytes
}

///|
pub fn Stanza::new(
  kind~ : String,
  args~ : Array[String],
  body~ : Bytes,
) -> Self {
  { kind, args, body, }
}

///|
/// The randomness a file needs, handed in by the caller rather than drawn here.
///
/// This library holds no entropy source: which one is right depends on the
/// platform, and a library that quietly picks one is a library that quietly
/// picks a bad one on the platform nobody tested. A `Recipient` draws from this
/// pool as it wraps; `moonseal` says how much a file needs before it starts.
pub struct Entropy {
  priv pool : Bytes
  priv mut used : Int32
}

///|
/// A pool of randomness. The bytes are consumed in order: a file key first, then
/// whatever each recipient type needs, then the payload nonce.
pub fn Entropy::new(bytes : BytesView) -> Self {
  { pool: bytes.to_owned(), used: 0, }
}

///|
/// The next `len` bytes, or a refusal if the pool is shorter than that. The
/// refusal is checked before anything is written, so a caller that hands in too
/// little gets a clean failure rather than a file encrypted with half a key.
pub fn Entropy::take(self : Entropy, len~ : Int32) -> BytesView raise Refused {
  if self.used + len > self.pool.length() {
    raise Refused::Entropy(want=len, got=self.pool.length() - self.used)
  }
  let taken = self.pool.clamped_view(start=self.used, end=self.used + len)
  self.used = self.used + len
  taken
}

///|
/// How many bytes are left.
pub fn Entropy::left(self : Entropy) -> Int32 {
  self.pool.length() - self.used
}

///|
/// A recipient type, from the encrypting side: it takes the file key and wraps
/// it into a stanza only the matching identity can unwrap.
///
/// `entropy` is where the ephemeral material comes from. It is passed rather
/// than created so that a caller can seal a file reproducibly, and so that the
/// pool is shared across the stanzas of one file instead of each type finding
/// its own.
pub(open) trait Recipient {
  fn wrap(Self, file_key~ : BytesView, entropy~ : Entropy) -> Stanza raise Refused
}

///|
/// A recipient type, from the decrypting side: given a stanza, either the file
/// key or `None` for "not mine, try the next one".
///
/// A stanza of a type this identity does not implement is `None`, and so is one
/// that is well formed but sealed to another key. A stanza that claims to be
/// this type and is malformed is a refusal, because at that point the file is
/// broken rather than addressed to somebody else.
pub(open) trait Identity {
  fn unwrap(Self, stanza~ : Stanza) -> Bytes? raise Refused
}
