// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The vectors of BIP 173, copied as they are printed there: seven strings that
/// are bech32, twelve that are not, each for a reason the encoder has to have
/// an opinion about.
test "bip 173: these are bech32" {
  let valid = [
    "A12UEL5L", "a12uel5l", "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
    "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw", "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
    "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w", "?1ezyfcl",
  ]
  for text in valid {
    let (hrp, words, variant) = @bech32.decode(text) catch {
      _ => fail("cannot decode " + text)
    }
    assert_eq(variant, @bech32.Bech32)
    // And back out again: one word string has exactly one lowercase spelling.
    assert_eq(
      @bech32.encode_words(hrp, words, variant=@bech32.Bech32),
      text.to_lower(),
    )
  }
}

///|
test "bip 173: these are not bech32" {
  let invalid = [
    "\u{20}1nwldj5", "\u{7f}1axkwrx", "\u{80}1eym55h", "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
    "pzry9x0s0muk", "1pzry9x0s0muk", "x1b4n0q5v", "li1dgmt3", "de1lg7wt\u{ff}", "A1G7SGD8",
    "10a06t8", "1qzzfhee",
  ]
  for text in invalid {
    let decoded = Some(@bech32.decode(text)) catch { _ => None }
    assert_true(
      decoded is None,
      msg="decoded " + text + ", which BIP 173 rejects",
    )
  }
}

///|
/// The bech32m strings of BIP 350. None of them is valid bech32, which is what
/// the variant the decoder reports is for.
test "bip 350: these are bech32m" {
  let valid = [
    "A1LQFN3A", "a1lqfn3a", "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
    "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx", "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
    "split1checkupstagehandshakeupstreamerranterredcaperredlc445v", "?1v759aa",
  ]
  for text in valid {
    let (hrp, words, variant) = @bech32.decode(text) catch {
      _ => fail("cannot decode " + text)
    }
    assert_eq(variant, @bech32.Bech32m)
    assert_eq(
      @bech32.encode_words(hrp, words, variant=@bech32.Bech32m),
      text.to_lower(),
    )
  }
}

///|
test "bip 350: these are not bech32m" {
  let invalid = [
    "\u{20}1xj0phk", "\u{7f}1g6xzxy", "\u{80}1vctc34", "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
    "qyrz8wqd2c9m", "1qyrz8wqd2c9m", "y1b0jsk6g", "lt1igcx5c0", "in1muywd", "mm1crxm3i",
    "au1s5cgom", "M1VUXWEZ", "16plkw9", "1p2gdwpf",
  ]
  for text in invalid {
    let decoded = Some(@bech32.decode(text)) catch { _ => None }
    assert_true(
      decoded is None,
      msg="decoded " + text + ", which BIP 350 rejects",
    )
  }
}

///|
/// The addresses BIP 350 lists as carrying the other checksum. They decode —
/// the encoding is fine — but not as the variant the address needs, which is
/// why a decoder has to say which one it found.
test "bip 350: the wrong variant is visible" {
  let cases = [
    (
      "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
      @bech32.Bech32,
    ),
    ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh", @bech32.Bech32m),
  ]
  for entry in cases {
    let (_, _, variant) = @bech32.decode(entry.0) catch {
      _ => fail("cannot decode " + entry.0)
    }
    assert_eq(variant, entry.1)
  }
}

///|
/// A key is eight bits at a time, so it goes through the byte form — and comes
/// back as the same string whichever case it was written in.
test "a recipient round trips in either case" {
  let key = Bytes::make(32, 0x42)
  let lower = @bech32.encode("age", key, variant=@bech32.Bech32)
  assert_true(lower.has_prefix("age1"))
  assert_eq(lower.length(), 62)
  let (hrp, data, _) = @bech32.decode_bytes(lower) catch { _ => abort("no") }
  assert_eq(hrp, "age")
  assert_eq(data, key)
  let upper = @bech32.encode("AGE-SECRET-KEY-", key, variant=@bech32.Bech32)
  assert_true(upper.has_prefix("AGE-SECRET-KEY-1"))
  let (hrp, back, _) = @bech32.decode_bytes(upper) catch { _ => abort("no") }
  assert_eq(hrp, "age-secret-key-")
  assert_eq(back, key)
}

///|
test "panic mixing case" {
  ignore(@bech32.encode("aGe", Bytes::make(1, 0), variant=@bech32.Bech32))
}

///|
test "panic encoding something too long" {
  ignore(@bech32.encode("age", Bytes::make(100, 0), variant=@bech32.Bech32))
}

///|
test "panic an empty human-readable part" {
  ignore(@bech32.encode("", Bytes::make(1, 0), variant=@bech32.Bech32))
}
