// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A recipient type that lives outside the library, to show what adding one takes:
/// a name for the stanza, a way to wrap the file key, and a way to unwrap it.
///
/// This one is a shared secret — the kind of thing a plugin for a team's own key
/// service would be. A new type is a new package: nothing in this library has to
/// know it exists, because the header carries stanzas it does not understand and
/// an identity only answers for the types it implements.
///
///     moon run src/examples/recipient

///|
let kind : String = "example.com/shared-secret"

///|
let context : Bytes = b"example.com/shared-secret/v1"

///|
let sha256 : () -> &@cryptspec.Hash = fn() -> &@cryptspec.Hash {
  @sha2.Hasher::new()
}

///|
/// The key the file key is wrapped under: the shared secret, bound to the salt
/// that identifies this stanza.
fn wrap_key(secret : BytesView, salt : BytesView) -> Bytes {
  @hkdf.key(secret, sha256, salt~, info=context, len=32)
}

///|
struct Recipient {
  secret : Bytes
}

///|
impl @spec.Recipient for Recipient with fn wrap(self, file_key~, random~) {
  let salt = @spec.draw(random, 16)
  let key = wrap_key(self.secret, salt)
  let aead = @chachapoly.ChaChaPoly::new(key) catch { _ => abort("no") }
  @spec.Stanza::new(
    kind~,
    args=[hex_of(salt)],
    body=aead.seal(nonce=Bytes::make(12, 0), plain=file_key, aad=b""),
  )
}

///|
struct Identity {
  secret : Bytes
}

///|
impl @spec.Identity for Identity with fn unwrap(self, stanza~) {
  if stanza.kind != kind {
    return None
  }
  let salt = hex_decode(stanza.args[0])
  let key = wrap_key(self.secret, salt)
  let aead = @chachapoly.ChaChaPoly::new(key) catch { _ => abort("no") }
  return Some(
    aead.open(nonce=Bytes::make(12, 0), cipher=stanza.body[:], aad=b"") catch {
      _ => return None
    },
  )
}

///|
/// The salt as text, since an argument is printable ASCII and nothing else.
fn hex_of(bytes : BytesView) -> String {
  let out = StringBuilder(size_hint=bytes.length() * 2)
  for byte in bytes {
    let value = byte.to_int()
    out.write_char(digit(value >> 4))
    out.write_char(digit(value & 0x0F))
  }
  out.to_string()
}

///|
fn digit(value : Int32) -> Char {
  (if value < 10 { 48 + value } else { 87 + value }).unsafe_to_char()
}

///|
fn hex_decode(text : StringView) -> Bytes {
  let units = text.code_units()
  let out = Array(capacity=units.length() / 2)
  let mut i = 0
  while i + 1 < units.length() {
    out.push(((nibble(units[i]) << 4) | nibble(units[i + 1])).to_byte())
    i = i + 2
  }
  Bytes::from_array(out)
}

///|
fn nibble(unit : UInt16) -> Int32 {
  if unit >= 48 && unit <= 57 {
    (unit - 48).to_int()
  } else if unit >= 97 && unit <= 102 {
    (unit - 87).to_int()
  } else {
    0
  }
}

///|
#coverage.skip
fn main {
  run() catch {
    error => println("refused: \{error}")
  }
}

///|
#coverage.skip
fn run() -> Unit raise @spec.Refused {
  let secret = b"the shared secret the team keeps"[:]
  let file = @moonseal.seal(
    [Recipient::{ secret: secret.to_owned(), }],
    b"the quick brown fox\n",
    random=@system.source,
  )
  println("sealed: \{file.length()} bytes")
  println(
    "opened: " +
    @utf8.decode_lossy(
      @moonseal.open([Identity::{ secret: secret.to_owned(), }], file),
    ),
  )
  // A different secret is a different file: the stanza opens to nothing.
  match
    (Some(
      @moonseal.open(
        [Identity::{ secret: b"another secret"[:].to_owned(), }],
        file,
      ),
    ) catch {
      error => {
        println("the wrong secret gets: \{error}")
        None
      }
    }) {
    Some(_) => println("the wrong secret opened it, which cannot happen")
    None => ()
  }
}
