// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The identity and recipient the specification publishes as an example, which
/// is the cheapest way to check that both halves of the seed expand the way
/// every other implementation expands them.
let example_identity : String = "AGE-SECRET-KEY-PQ-1XX76JRALNLXDMEW0CRK45QMCCH4X06SE84UN3VPM33W6HWDX0H3SK3ZQFR"

///|
let example_recipient : String = "age1pq1x34nzsvr0rxjsgdn8zgyhfe8j7ceq5r9rdelkjuh3y235jzxshfg87pzf5zrqtzdxz95paef6caq5aapdmwjjqpjfdyxnzr2zampc3uxy0dg4z2n2gm9su72p0pc3u0jvev55l694v78snxg3yzvcl7yda0eyytqj6a0ec477lnhcy5hzpz4zq3pxanve4cn62gqj3pjy5lqj9c6kyj4v2z8alktn8zh99970x79gjkv7522hv9kfz35zsnxhsx8wwtmu9cy3ftzjgwcp4sshn3llnylnpdsyz5jm72vefv4x5vfwytrefxg4wq3mv42wcrvkj742479zrxzpvp2p3e9fed9f0739vcu80r7ma28qfhnvlv4gfzel9q654dj3zmuvvz893azhxdvs9fxd0r7jzchzcfcs5mkyyjxhw0n2z6dvp9yn9qfdp29h0azxqyjw6v7fhyuzj7zel0uq6j9rd7wgrpz7mf5dnj43jwsgvrc8qcnhy7tu6dkdujuxzkp9xj43xe8h92ktre2a3u3s8mm5mrp9nr9pwkgtz4mdlq9hgn4fps4k57ff6wddn2fy23t47sm20r8km8sd2pcyyafnet8f0dajsrlyjeah4n3mssr6aseevuuskdvq5lzguyvpgwpta742c6698vgutzqgny8usfg0w2he7kq5vyxjd0f9hqg8xk26y9e4th0gezq92q4cpp5p2y9hf5f2cje5l0c3sa3a2qxmm38pxxvhxh99yzmfz0zk7r2s64nnwjhkfgfr3gf8xnmppcgmaykvh5sh6g7vk9790rf8ws0axmr2t7z8aae5fq2029uvcn2ghgt4fu4wgwdc0k0cz52qkvwmuzj8p8k5jgf3xzk5zmrkavjekjrpeq408xz3zxazwkc6tyfmhayrkfpjhwtz5mp8j8guqe43k2q6m2kte03vrw27y3wmqyu5etmt9dnkwcnnpmu9gz9dekfhdevf42ucshphnrk38ra6hx8w5f8q5ru0xdhrjxmwqf6cused7zc5xvq43r0zscjglpwlptpwydhqw64xz7ptjdyeyzpq2zkxtmzg29gzjpvzva4d3l0cenn9xs297wf4y4ukwrunf57xj6pm7nvrkwvtrt8hwcmgv8x7ajw7258ugf9wvkmk4052ekg87tw5vnx8nq2swyzv77v8yqlwsenvamr0zssknwts8rrhfuwj7ykysnq9jxy0uv3kuyt22djszjdtvpz6d0s0kwh8ryynddzud92emeyvvyqktd0jtj7rvvg5gch25v8smlvny3kvn5gagyz475ze2y6q466xqmz2n3hs77lddeqyta2nch5k2u5yacuk9ywnwfdzvyejnucz724hj77hrrmakm7pr3kxsrxq22ejexlud9fy2kdqmkg5yncz7jm5wv2qjk5w5kvcpqsry2yqffh2la52dxfjkjq5rzhjzeyn6dupn0qwtyv7s4lwg3xdarsdlwe2y3tujy480y7z39q259fzx6jhd2j0f5hagqpcpees7hzc2yrk5cy788uk3s7qvp5cpepx24gvws3m2g433exgwppnkjscec8qu4y9z9r7vccexjcjaen42245lmgmxmuavg9alej92322gvvyy2t6267v09ch64y0m53jff0vjj96s0ypk60hr3jw4myd6m5hpn3xjstx7tl2szhpr5qe8jj08ydjc4wy2rch2fhuy3pdfjax5awe9j99ly5hkntzz9fe5zatgjvzdd0kgtxs25njnajyf6ssekp7gelxquusn4pt25czh3scj68kq79wdn5tgm6yvm9nzavrg043x3msnygf8dweknw5jmqd0uvny6ttsn09508k0c55zfnegrm9efhxpfqdkmhh6gjtqmwze9pyyzk3tlhl53k2ykx3qheyty7saeq0d3fzv49zc0k"

///|
/// Randomness that is the same every time.
fn pool(bytes : Int32, seed : Int32) -> @moonseed.Replay {
  @moonseed.Replay::new(
    Bytes::from_array(
      Array::makei(bytes, fn(i) { ((i * 37 + seed * 11) % 256).to_byte() }),
    ),
  )
}

///|
test "the published identity derives the published recipient" {
  let identity = @mlkem768x25519.Identity::of(example_identity) catch {
    error => fail("cannot read the identity: \{error}")
  }
  assert_eq(identity.public().code(), example_recipient)
  assert_eq(identity.code(), example_identity)
}

///|
test "a file sealed to a post-quantum recipient opens for it" {
  let identity = @mlkem768x25519.Identity::of(example_identity) catch {
    _ => abort("no")
  }
  let recipients : Array[&@spec.Recipient] = [identity.public()]
  let file = @moonseal.seal(
    recipients,
    b"for after the quantum",
    random=pool(256, 1),
  ) catch {
    error => fail("cannot seal: \{error}")
  }
  let readers : Array[&@spec.Identity] = [identity]
  assert_eq(@moonseal.open(readers, file), b"for after the quantum")
}

///|
test "a file addressed to another post-quantum key does not open" {
  let mine = @mlkem768x25519.Identity::of(example_identity) catch {
    _ => abort("no")
  }
  let theirs = @mlkem768x25519.Identity::of(
    "AGE-SECRET-KEY-PQ-1HZLGZUPT4ETPKDEV8HSGFDCYZ4E522W0A7PU2LHT8EH9W6YLNC3SW78XKG",
  ) catch {
    _ => abort("the vector's identity does not parse")
  }
  let recipients : Array[&@spec.Recipient] = [theirs.public()]
  let file = @moonseal.seal(recipients, b"not for me", random=pool(256, 2)) catch {
    _ => abort("no")
  }
  let readers : Array[&@spec.Identity] = [mine]
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
test "a malformed post-quantum stanza is a refusal" {
  let identity = @mlkem768x25519.Identity::of(example_identity) catch {
    _ => abort("no")
  }
  let short = @spec.Stanza::new(
    kind="mlkem768x25519",
    args=[],
    body=Bytes::make(32, 0),
  )
  let refused = try {
    ignore(identity.unwrap(stanza=short))
    false
  } catch {
    @spec.Refused::Stanza(..) => true
    _ => false
  }
  assert_true(refused)
}
