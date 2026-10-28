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
    Entropy(..) | Limit(..) => @cctv.Skipped
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
/// Run one case and say what happened: the category of the outcome, and the
/// plaintext when there is one.
fn attempt(vector : @cctv.Vector) -> (@cctv.Expect, Bytes) {
  let file = @base64.decode_padded(vector.data) catch {
    _ => return (@cctv.Skipped, b"")
  }
  let identities : Array[&@spec.Identity] = []
  for text in vector.identities {
    identities.push(@x25519.Identity::of(text) catch { _ => continue })
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
    let (got, plain) = attempt(vector)
    if got != vector.expect {
      failures.push("\{vector.name}: expected \{vector.expect}, got \{got}")
    } else if got == @cctv.Success {
      let digest = @hex.encode(@sha2.hash(plain))
      if digest != vector.digest {
        failures.push("\{vector.name}: opened to the wrong bytes")
      }
    }
  }
  println("cctv: \{ran} cases ran, \{skipped} skipped")
  assert_true(failures.length() == 0, msg=failures.join("\n"))
}
