// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The four worked examples of RFC 7914 §12. The fourth needs a mebibyte of
/// scratch space for every kilobyte of the third, which is why it is not run
/// here: 2^20 · 1024 bytes is one gibibyte, more than a test binary should ask
/// for. The first three pin every code path — a single iteration, several
/// parallel passes, and the full-size buffer.
test "rfc 7914 section 12" {
  let cases : Array[(String, String, Int32, Int32, Int32, String)] = [
    (
      "", "", 4, 1, 1, "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
    ),
    (
      "password", "NaCl", 10, 8, 16, "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
    ),
    (
      "pleaseletmein", "SodiumChloride", 14, 8, 1, "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
    ),
  ]
  for case in cases {
    let (password, salt, log_n, r, p, expected) = case
    let got = @kdf.key(
      @utf8.encode(password),
      @utf8.encode(salt),
      log_n~,
      r~,
      p~,
      len=64,
    )
    assert_eq(@hex.encode(got), expected)
  }
}
