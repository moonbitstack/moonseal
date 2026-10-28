// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The whole surface in one run, so a reader can see what this is for before
/// reading any of it.
///
///     moon run src/examples/tour

///|
/// A stand-in for the platform's random source.
///
/// This library holds no entropy of its own: which source to use is a platform
/// question, and guessing wrong is silent rather than loud. In a real program
/// these bytes come from the operating system; here they come from a counter so
/// that the run is the same every time.
#coverage.skip
fn bytes(len : Int32, seed : Int32) -> Bytes {
  Bytes::from_array(
    Array::makei(len, fn(i) { ((i * 13 + seed * 29) % 256).to_byte() }),
  )
}

///|
#coverage.skip
fn pool(len : Int32, seed : Int32) -> @spec.Entropy {
  @spec.Entropy::new(bytes(len, seed))
}

///|
#coverage.skip
fn text(bytes : Bytes) -> String {
  @utf8.decode_lossy(bytes)
}

///|
#coverage.skip
fn main {
  tour() catch {
    error => println("refused: \{error}")
  }
}

///|
#coverage.skip
fn tour() -> Unit raise @spec.Refused {
  // Two readers with public keys. The same file opens for either of them.
  let alice = @x25519.Identity::new(bytes(32, 1))
  let bob = @x25519.Identity::new(bytes(32, 2))
  let recipients : Array[&@spec.Recipient] = [alice.public(), bob.public()]
  println("alice's public key: \{alice.public().code()}")
  println("alice's secret key: \{alice.code()}")
  let file = @moonseal.seal(
    recipients,
    b"the quick brown fox\n",
    entropy=pool(256, 3),
  )
  println("sealed: \{file.length()} bytes")

  // Either of them opens it.
  let mine : Array[&@spec.Identity] = [bob]
  println("bob reads: \{text(@moonseal.open(mine, file))}")

  // A passphrase is a recipient type of its own, and has to be alone: a file
  // under one is a file whose only reader is whoever knows it.
  let sealed_with_passphrase = @moonseal.seal(
    [@scrypt.Recipient::new("correct horse battery staple", log_n=10)],
    b"the quick brown fox\n",
    entropy=pool(64, 5),
  )
  let passphrase : Array[&@spec.Identity] = [
    @scrypt.Identity::new("correct horse battery staple"),
  ]
  println(
    "the passphrase reads: \{text(@moonseal.open(passphrase, sealed_with_passphrase))}",
  )

  // Somebody else does not.
  let stranger : Array[&@spec.Identity] = [@x25519.Identity::new(bytes(32, 9))]
  let attempt = Some(@moonseal.open(stranger, file)) catch {
    error => {
      println("a stranger gets: \{error}")
      None
    }
  }
  if attempt is Some(_) {
    println("a stranger opened it, which cannot happen")
  }

  // The same file as text, for the places a binary cannot go.
  let armored = @moonseal.seal_armored(
    [alice.public()],
    b"hello from an email\n",
    entropy=pool(128, 4),
  )
  println(armored)
  println("and back: \{text(@moonseal.open_armored([alice], armored))}")
}
