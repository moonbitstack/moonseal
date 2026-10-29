// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The randomness the C2SP vectors were generated with: a ChaCha20 keystream
/// under a fixed key, drawn in the order a file asks for it.
///
/// Reproducing it is what turns "we can open their files" into "we write theirs":
/// sealing the same plaintext to the same recipient with this pool has to give
/// the vector's bytes exactly, MAC line and all.
fn test_entropy(bytes : Int32) -> Bytes {
  let stream = @chacha20.Cipher::new(b"TEST RANDOMNESS TEST RANDOMNESS!"[:]) catch {
    _ => abort("unreachable")
  }
  let zeros = Bytes::make(bytes, 0)
  let noise = stream.xor(nonce=Bytes::make(12, 0), zeros, counter=0) catch {
    _ => abort("unreachable")
  }
  b"YELLOW SUBMARINE".add(noise)
}

///|
/// The vector of that name, from the same table the conformance test reads.
fn vector(name : String) -> @cctv.Vector {
  for vector in @cctv.vectors {
    if vector.name == name {
      return vector
    }
  }
  abort("no vector named " + name)
}

///|
/// An X25519 file, written here, byte for byte the one the vectors publish.
///
/// Everything the format leaves to the sender is pinned by this: the order the
/// file key and the ephemeral share are drawn in, the salt and context of the
/// wrap key, the column at which the body is wrapped, and what the MAC covers.
test "interop: our x25519 file is the reference file" {
  let case = vector("x25519")
  let identity = @x25519.Identity::of(case.identities[0]) catch {
    _ => abort("the vector's identity does not parse")
  }
  let written = @moonseal.seal(
    [identity.public()],
    b"age",
    random=@moonrand.Replay::new(test_entropy(64)),
  ) catch {
    error => fail("seal refused: \{error}")
  }
  let published = @base64.decode(case.data, padding=true, strict=true) catch {
    _ => abort("no")
  }
  assert_eq(written, published)
}

///|
/// The same for a passphrase, whose stanza carries a salt and a work factor
/// instead of a share.
test "interop: our scrypt file is the reference file" {
  let case = vector("scrypt")
  let written = @moonseal.seal(
    [@scrypt.Recipient::new("password", log_n=10)],
    b"age",
    random=@moonrand.Replay::new(test_entropy(64)),
  ) catch {
    error => fail("seal refused: \{error}")
  }
  let published = @base64.decode(case.data, padding=true, strict=true) catch {
    _ => abort("no")
  }
  assert_eq(written, published)
}

///|
/// And the plaintext the vectors were built with is what a file we write holds,
/// which is the other direction of the same statement.
test "interop: the file we write opens to the vector's bytes" {
  let case = vector("x25519")
  let published = @base64.decode(case.data, padding=true, strict=true) catch {
    _ => abort("no")
  }
  let identities : Array[&@spec.Identity] = [
    @x25519.Identity::of(case.identities[0]) catch {
      _ => abort("the vector's identity does not parse")
    },
  ]
  let plain = @moonseal.open(identities, published) catch {
    error => fail("open refused: \{error}")
  }
  assert_eq(@hex.encode(@sha2.hash(plain)), case.digest)
}
