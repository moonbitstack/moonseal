// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// What the test vectors call each kind of failure, in this library's terms.
fn category(error : @spec.Refused) -> @cctv.Expect {
  match error {
    Header(..) | Stanza(..) | Key(..) => @cctv.HeaderFailure
    Mac => @cctv.MacFailure
    NoMatch => @cctv.NoMatch
    Payload(..) => @cctv.PayloadFailure
    Armor(..) => @cctv.ArmorFailure
    Random(_) | Limit(..) => @cctv.Skipped
  }
}

///|
/// The file, opened the way the case was written.
fn opened(
  vector : @cctv.Vector,
  identities : Array[&@spec.Identity],
  file : Bytes,
) -> Bytes raise @spec.Refused {
  if vector.armored {
    @moonseal.open_armored(identities, decoded(file))
  } else {
    @moonseal.open(identities, file)
  }
}

///|
/// The armored vectors are ASCII by construction; anything else has already
/// failed the armor's own character check by the time this is read.
fn decoded(bytes : BytesView) -> StringView {
  @utf8.decode_lossy(bytes)
}

///|
/// One identity a case names, which is one of the two key types the format
/// spells in bech32. A case whose key does not parse is not a case at all: the
/// refusal is handed up rather than treated as "not mine", so that a broken key
/// type shows up as a failing vector instead of a quietly skipped identity.
fn identity_of(text : String) -> &@spec.Identity raise @spec.Refused {
  if text.has_prefix("AGE-SECRET-KEY-PQ-") {
    let identity : &@spec.Identity = @mlkem768x25519.Identity::of(text)
    return identity
  }
  let identity : &@spec.Identity = @x25519.Identity::of(text)
  identity
}

///|
/// Run one case and say what happened: the category of the outcome, and the
/// plaintext when there is one.
fn attempt(vector : @cctv.Vector) -> (@cctv.Expect, Bytes) raise @spec.Refused {
  let file = @base64.decode(vector.data, padding=true, strict=true) catch {
    _ => raise @spec.Refused::Header(at=0, want="a base64 file")
  }
  let identities : Array[&@spec.Identity] = []
  for text in vector.identities {
    identities.push(identity_of(text))
  }
  for text in vector.passphrases {
    identities.push(@scrypt.Identity::new(text))
  }
  let plain = opened(vector, identities, file) catch {
    error => return (category(error), b"")
  }
  (@cctv.Success, plain)
}

///|
/// Every case in the C2SP age test vectors.
///
/// A case is either a file that has to open and hash to a given digest, or a
/// file that has to be refused for a given reason. Both halves matter: a reader
/// that opens everything is as wrong as one that opens nothing.
test "cctv: the age test vectors" {
  let mut ran = 0
  let mut skipped = 0
  let failures = Array(capacity=4)
  for vector in @cctv.vectors {
    if vector.expect == @cctv.Skipped {
      skipped = skipped + 1
      continue
    }
    ran = ran + 1
    let outcome = Ok(attempt(vector)) catch { error => Err(error) }
    match outcome {
      Err(error) =>
        failures.push("\{vector.name}: cannot run the case: \{error}")
      Ok((got, plain)) =>
        if got != vector.expect {
          failures.push("\{vector.name}: expected \{vector.expect}, got \{got}")
        } else if got == @cctv.Success {
          let digest = @hex.encode(@sha2.hash(plain))
          if digest != vector.digest {
            failures.push("\{vector.name}: opened to the wrong bytes")
          }
        }
    }
  }
  println("cctv: \{ran} cases ran, \{skipped} skipped")
  assert_true(failures.length() == 0, msg=failures.join("\n"))
}
