// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The string the age test plugin is named after, which its identity is derived
/// from. Every published value below follows from these bytes.
let seed : Bytes = b"age-plugin-tagtest"

///|
/// That identity's public half, as the reference implementation writes it.
let published : String = "age1tagpq14h4z7cks9sxftfc8tq4xektt4854ur9rv76tvujdvtzk2fmyywkvh9z2emz3x4epvhz7qdt2v7uksyyq2cdzf3k04ny0g5sc3u4heqh3r9v4cnwhfjw0a2azpgmnk9xk02wvywt5szcq6q3jvwsjxvkn3tsk52vqjczdcvc398ym4j6cvqas4w99gkgt7ur3fmt4g873phr23tgxw3f7wgsz9zxz7m8cp27vpq3h5vc8nssjemtr2etmtmqkg4fzn2u9x9zvtysuya5yrytgx482ftx9864h8a6pprarxd3d0qe8nw2at5ekg3tsahtef7kawasxjamyckw2ans6v933vuypcfrra32f89r2v72mka9hhc55s49xe2khfsq7w9r2zynuzfx4fg6v7jjncsc87rw2yy8qp8hr27edus6zw5xd6m3hax2nxhl2dys9792z3wp5c034sfkrxe86guj7pfdh7sytzrufl9euhuhyf9w6c7z2nwf7v5v8f2s4gplgvfx4jj4le22k2qn242qkqkcwx7llfyrct7jm2wcv0ytypeh6h93ezgtd7q6zr428qze3dec5jxlc5xxjetyephp42fljft3s02p0570kjwyfeyjcnks2vglkvyus5g9l4z6m0gf8wu22ygfm40028txwjlxvvgnn7c36z783c6tmc9k5nef8nucj6u3ustff5vhtnzhnscsvsz79wzrkv3sujtntx4wezucy6lp49flmnyydn3khk2xsesw0ekn4u44nzqw2g2rjyrrl7crshlzttgpe0jvqycjzp9kmtz23t3yu0w9j4n344nnrf88k2jqqfpjxte38pcn0epr879pqsuvajxrkmsas89pvfrzwcewneujn08guj5pvvrtn5hzzg2y6u4wwjqqxx4x8w65yc4dchf750dft8kgcttt2f6j0j5v8s7tkaua78tte7artdfar544vl0rau79h95mc4ghp887z82s6rq93txpkvan86n963kagqkldngnkjcn28zdrh38vdxj002zqs9mx7zjvg3ynzdfhfakkynt9fyqpaxpsdrsqrycuhw5ykwgjz6wldef7xtu6p689234hstxe7v8e5422f2dy8ystn57z3fvy9yfrm4t3lye6ejk5n6x8zqexmql7lx965xcxuuy38xzyt8j9qprnwgfqgx54l4tnjdpzdde6xgmwtnpkfwvyr7rkgnavvjn6a3e56wtvjx3evmhjjxvukpq5zqrj0s4sntkz3yeszs5dty8q0q6m7dgp6mjpvaer0c4343g72eycfqzkjupeaemh0n8e935hqs8fh3jgk7fzyxctzuqlx6d2q9jaf8r9wu4sjxj5w6ppw7m9c3hxrzpcv2uek3kxnndgf2hd99q9v2ux8pjkv29ntslvnvhy09dvcy9578rt89gf4cj4cu79zjxtlj3dpct6rjme02zj3qspsade96njkkufu9zuq2lk3qwvddpxjkqm2hnpqwck54zug7ctvkgvk325lwkg4q5rf73zkgys5e9y8jqc96ntdyl4r78lgtw4k5uljk5ttf46s3gc0rq0jwmddnxt875twwq92505zh3zkse5ag2dhjjxyfzkn7xv3j0kv9r3jzpvgep8fq6z8mar509u4fvnhvthp2ah0r45lsyq0mm6fwkcs30v8k9wzvgt6uvcty6qsjvarjs3htym69zu43m4jd3k4tllrr8c05v6p6spuhup4hkk2p9fp9lxafe3pntcn4nk83gzhjjpcjwyg7jcyz5uancu0fakgz27up7ymzp2xv3sqyqewkkqynskw9qkvysrncxj0cy7dt6q8dsseuwmc2urfmcvkykf82wfa54t85hqx8gywhmhzunm2x0d66a4pwl0xl78fhkces5dpq8pfnp35m5a3u8vdam64zx5s5x9cmnrx3zr066f4f8hlecqnq2fd5quw79ljg3q5nvs6ggmm4gkc"

///|
/// The seed the same derivation produces, in the reference implementation's
/// bytes: the check that both sides arrive at a key and not merely at a string.
let seed_hex : String = "2b3d0bf33efca0f3ce306af9a963d1d75cf447c971667d8ccabafc47b16c2ef2"

///|
/// Randomness that is the same every time.
fn pool() -> @moonseed.Replay {
  @moonseed.Replay::new(
    Bytes::from_array(
      Array::makei(512, fn(i) { ((i * 37 + 11) % 256).to_byte() }),
    ),
  )
}

///|
/// The identity behind the published recipient.
fn identity() -> @mlkem768p256tag.Identity {
  @mlkem768p256tag.Identity::from_seed(seed[:]) catch {
    error => abort("the seed does not derive: \{error}")
  }
}

///|
/// An encapsulation: 1088 bytes of ML-KEM ciphertext, then a P-256 point.
fn encapsulation() -> Bytes {
  let out = Array::makei(1153, fn(i) { (i % 251).to_byte() })
  out[1088] = b'\x04'
  Bytes::from_array(out)
}

///|
test "the seed derives the identity the reference implementation derives" {
  assert_eq(identity().public().code(), published)
  assert_eq(@hex.encode(identity().key()), seed_hex)
}

///|
test "a written recipient reads back to itself" {
  let recipient = @mlkem768p256tag.Recipient::of(published) catch {
    error => fail("the published recipient does not parse: \{error}")
  }
  assert_eq(recipient.code(), published)
  assert_eq(recipient.key().length(), @mlkem768p256tag.public_size)
  assert_eq(identity().public().code(), recipient.code())
}

///|
test "the tag of a known encapsulation is the one the reference computes" {
  let recipient = @mlkem768p256tag.Recipient::of(published) catch {
    _ => abort("no")
  }
  assert_eq(@hex.encode(recipient.tag(encapsulation())), "d3f8ac2a")
}

///|
test "a file sealed to a hybrid tagged recipient opens for it" {
  let reader = identity()
  let recipients : Array[&@spec.Recipient] = [reader.public()]
  let file = @moonseal.seal(
    recipients,
    b"for the key on the desk, after the quantum",
    random=pool(),
  ) catch {
    error => fail("cannot seal: \{error}")
  }
  let readers : Array[&@spec.Identity] = [reader]
  assert_eq(
    @moonseal.open(readers, file),
    b"for the key on the desk, after the quantum",
  )
}

///|
test "a file addressed to another hybrid tagged key does not open" {
  let theirs = @mlkem768p256tag.Identity::generate(random=pool()) catch {
    _ => abort("no randomness")
  }
  let recipients : Array[&@spec.Recipient] = [theirs.public()]
  let file = @moonseal.seal(recipients, b"not for me", random=pool()) catch {
    _ => abort("cannot seal")
  }
  let readers : Array[&@spec.Identity] = [identity()]
  let refused = try {
    ignore(@moonseal.open(readers, file))
    false
  } catch {
    @spec.Refused::NoMatch => true
    _ => false
  }
  assert_true(refused)
}

///|
test "a hybrid tagged stanza carries the tag and the encapsulation" {
  let reader = identity()
  let recipients : Array[&@spec.Recipient] = [reader.public()]
  let file = @moonseal.seal(recipients, b"x", random=pool()) catch {
    _ => abort("cannot seal")
  }
  let (head, _) = @header.Header::decode(file) catch { _ => abort("no header") }
  let stanza = head.stanzas()[0]
  assert_eq(stanza.kind, "mlkem768p256tag")
  assert_eq(stanza.args.length(), 2)
  let tag = @base64.decode(stanza.args[0], padding=false, strict=true) catch {
    _ => abort("no tag")
  }
  assert_eq(tag.length(), 4)
  let enc = @base64.decode(stanza.args[1], padding=false, strict=true) catch {
    _ => abort("no encapsulation")
  }
  assert_eq(enc.length(), 1153)
  assert_eq(stanza.body.length(), 32)
}

///|
test "a malformed hybrid tagged stanza is a refusal, not somebody else's" {
  let reader = identity()
  let cases : Array[@spec.Stanza] = [
    @spec.Stanza::new(kind="mlkem768p256tag", args=[], body=Bytes::make(32, 0)),
    @spec.Stanza::new(
      kind="mlkem768p256tag",
      args=["AAAA"],
      body=Bytes::make(32, 0),
    ),
    @spec.Stanza::new(
      kind="mlkem768p256tag",
      args=["AAAA", "AAAA"],
      body=Bytes::make(32, 0),
    ),
    @spec.Stanza::new(
      kind="mlkem768p256tag",
      args=["AAAA", @base64.encode(encapsulation(), padding=false)],
      body=Bytes::make(33, 0),
    ),
  ]
  for stanza in cases {
    let refused = try {
      ignore(reader.unwrap(stanza~))
      false
    } catch {
      @spec.Refused::Stanza(..) => true
      _ => false
    }
    assert_true(refused)
  }
}

///|
test "a stanza of the plain tagged type is not this identity's" {
  let stanza = @spec.Stanza::new(
    kind="p256tag",
    args=["AAAA", "AAAA"],
    body=Bytes::make(32, 0),
  )
  assert_eq(identity().unwrap(stanza~) is None, true)
}

///|
test "a tag that names another key is passed over without the key being used" {
  let other = @mlkem768p256tag.Identity::generate(random=pool()) catch {
    _ => abort("no randomness")
  }
  let stanza = @spec.Stanza::new(
    kind="mlkem768p256tag",
    args=[
      @base64.encode(other.public().tag(encapsulation()), padding=false),
      @base64.encode(encapsulation(), padding=false),
    ],
    body=Bytes::make(32, 0),
  )
  assert_eq(identity().unwrap(stanza~) is None, true)
}

///|
test "a key whose point is not on the curve is refused as a recipient" {
  let key = Array::makei(1249, fn(_) { b'\x00' })
  let refused = try {
    ignore(@mlkem768p256tag.Recipient::new(Bytes::from_array(key)))
    false
  } catch {
    @spec.Refused::Stanza(..) => true
    _ => false
  }
  assert_true(refused)
}

///|
test "a written recipient of the wrong kind is refused" {
  let texts : Array[String] = [
    "age1tag1qwe0kafsjrar4txm6heqnhpfuggzr0gvznz7fvygxrlq90u5mq2pysxtw6h", "age1pq1x34nzsvr0rxjsgdn8zgyhfe8j7ceq5r9rdelkjuh3y235jzxshfg87pzf",
  ]
  for text in texts {
    let refused = try {
      ignore(@mlkem768p256tag.Recipient::of(text))
      false
    } catch {
      @spec.Refused::Stanza(..) => true
      _ => false
    }
    assert_true(refused)
  }
}
