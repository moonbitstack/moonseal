// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The work factor a file gets when nobody says otherwise: 2^18, which is 256
/// MiB of scratch space and about a second on the machine that wrote this.
pub let default_log_n : Int32 = 18

///|
/// The largest work factor a reader will accept. Four gibibytes of scratch
/// space is the point past which a file stops being something to open and starts
/// being something to defend against.
pub let max_log_n : Int32 = limit

///|
/// The same number, under a name `Identity::new`'s argument does not shadow.
let limit : Int32 = 22

///|
/// What an scrypt stanza calls itself, and the prefix the salt is extended with.
let kind : String = "scrypt"

///|
let context : Bytes = b"age-encryption.org/v1/scrypt"

///|
/// How long the salt is, and how long the wrapped body is.
let salt_size : Int32 = 16

///|
let body_size : Int32 = 32

///|
/// A passphrase, from the encrypting side.
pub struct Recipient {
  priv passphrase : Bytes
  priv log_n : Int32
}

///|
/// A recipient for a passphrase, with the work factor it should use.
///
/// The work factor is a parameter rather than a constant because it is the one
/// knob that trades a reader's time for a guesser's: raise it when the passphrase
/// is weak or the file will outlive the hardware.
pub fn Recipient::new(passphrase : StringView, log_n? : Int32) -> Self {
  let log_n = match log_n {
    Some(log_n) => log_n
    None => default_log_n
  }
  check_log_n(log_n)
  { passphrase: @utf8.encode(passphrase), log_n, }
}

///|
/// The work factor this recipient writes into the file.
pub fn Recipient::log_n(self : Recipient) -> Int32 {
  self.log_n
}

///|
pub extend Recipient with @spec.Recipient::{wrap}

///|
pub impl @spec.Recipient for Recipient with fn wrap(self, file_key~, random~) {
  let salt = @spec.draw(random, salt_size)
  let stanza_salt = @base64.encode(salt, padding=false)
  let key = stretch(self.passphrase, salt, self.log_n)
  @spec.Stanza::new(
    kind~,
    args=[stanza_salt, self.log_n.to_string()],
    body=@crypt.seal(key, zeros(), file_key),
  )
}

///|
/// A passphrase, from the decrypting side.
pub struct Identity {
  priv passphrase : Bytes
  priv ceiling : Int32
}

///|
/// An identity for a passphrase, and the largest work factor it will agree to
/// run. A file is allowed to ask for a high one; a reader is allowed to say no.
pub fn Identity::new(passphrase : StringView, max_log_n? : Int32) -> Self {
  let ceiling = match max_log_n {
    Some(log_n) => log_n
    None => limit
  }
  check_log_n(ceiling)
  { passphrase: @utf8.encode(passphrase), ceiling, }
}

///|
pub extend Identity with @spec.Identity::{unwrap}

///|
pub impl @spec.Identity for Identity with fn unwrap(self, stanza~) {
  if stanza.kind != kind {
    return None
  }
  guard stanza.args.length() == 2 else {
    raise @spec.Refused::Stanza(
      want="two arguments: the salt and the work factor",
    )
  }
  guard stanza.body.length() == body_size else {
    raise @spec.Refused::Stanza(want="a 32-byte body")
  }
  let salt = @base64.decode(stanza.args[0], padding=false, strict=true) catch {
    _ => raise @spec.Refused::Stanza(want="a base64 salt")
  }
  guard salt.length() == salt_size else {
    raise @spec.Refused::Stanza(want="a 16-byte salt")
  }
  let log_n = work_factor(stanza.args[1], ceiling=self.ceiling)
  let key = stretch(self.passphrase, salt, log_n)
  return @crypt.open(key, zeros(), stanza.body[:])
}

///|
/// The decimal in the third argument: digits only, no leading zero, and no larger
/// than the reader agreed to.
fn work_factor(
  text : StringView,
  ceiling~ : Int32,
) -> Int32 raise @spec.Refused {
  let units = text.code_units()
  if units.length() == 0 {
    raise @spec.Refused::Stanza(want="a work factor")
  }
  if units[0] == 48 {
    raise @spec.Refused::Stanza(want="a work factor without a leading zero")
  }
  let mut value = 0
  for unit in units {
    if unit < 48 || unit > 57 {
      raise @spec.Refused::Stanza(want="a work factor in decimal digits")
    }
    value = value * 10 + (unit - 48).to_int()
    if value > limit {
      raise @spec.Refused::Stanza(want="a work factor of at most 22")
    }
  }
  if value > ceiling {
    raise @spec.Refused::Stanza(want="a work factor this reader accepts")
  }
  if value < 1 {
    raise @spec.Refused::Stanza(want="a work factor of at least 1")
  }
  value
}

///|
/// The scrypt key for a saltextended with this format's prefix.
fn stretch(passphrase : BytesView, salt : BytesView, log_n : Int32) -> Bytes {
  let params = @kdf.Params::new(n=1 << log_n, r=8, p=1)
  @kdf.key(passphrase, context.add(salt.to_owned()), params~, len=32)
}

///|
/// A work factor outside the range every implementation agrees on is a bug in
/// the caller rather than a condition to report, so it stops here.
fn check_log_n(log_n : Int32) -> Unit {
  if log_n < 1 || log_n > max_log_n {
    abort("scrypt: a work factor of 1 to \{max_log_n}, not \{log_n}")
  }
}

///|
/// The twelve zero bytes the wrap key is used with.
fn zeros() -> Bytes {
  Bytes::make(12, 0)
}
