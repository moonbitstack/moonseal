// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// SHA-256, which RFC 7914 §4 fixes as the hash underneath scrypt.
let sha256 : () -> &@spec.Hash = fn() -> &@spec.Hash { @sha2.Hasher::new() }

///|
/// The mask that keeps a word at thirty-two bits whatever `UInt` happens to be
/// on the backend in use.
let mask : UInt32 = 0xFFFFFFFFU

///|
/// The largest work factor this implementation will run. 2^22 needs four
/// gibibytes of scratch space, which is more than a process should take without
/// being asked; the format this library implements stops at the same number.
pub let max_log_n : Int32 = 22

///|
/// Scrypt itself: a password and a salt in, `len` bytes out, with `n = 2^log_n`
/// iterations over `128 · r · n` bytes of memory and `p` independent passes.
///
/// The parameters are checked rather than clamped, because a caller that asks
/// for a work factor beyond `max_log_n` has a bug, not a runtime condition.
pub fn key(
  password : BytesView,
  salt : BytesView,
  log_n~ : Int32,
  r~ : Int32,
  p~ : Int32,
  len~ : Int32,
) -> Bytes {
  if log_n < 1 || log_n > max_log_n {
    abort("scrypt: log_n must be between 1 and \{max_log_n}")
  }
  if r < 1 || p < 1 {
    abort("scrypt: r and p must be positive")
  }
  let n = 1 << log_n
  let block = 32 * r
  // PBKDF2 fills the memory buffer from the password; the mixing below then
  // works on it a word at a time.
  let initial = @pbkdf2.key(password, salt, sha256, rounds=1, len=p * block * 4)
  let words = FixedArray::make(p * block, 0U)
  for i in 0..<words.length() {
    words[i] = word_at(initial, i * 4)
  }
  let scratch = FixedArray::make(n * block, 0U)
  for i in 0..<p {
    romix(words, i * block, scratch, n, r)
  }
  let mixed = FixedArray::make(initial.length(), b'\x00')
  for i in 0..<words.length() {
    write_word(mixed, i * 4, words[i])
  }
  @pbkdf2.key(password, Bytes::from_array(mixed), sha256, rounds=1, len~)
}

///|
/// The four bytes at `at`, little-endian, as a word.
fn word_at(bytes : BytesView, at : Int32) -> UInt32 {
  (bytes[at].to_int() |
  (bytes[at + 1].to_int() << 8) |
  (bytes[at + 2].to_int() << 16) |
  (bytes[at + 3].to_int() << 24)).reinterpret_as_uint() &
  mask
}

///|
fn write_word(bytes : FixedArray[Byte], at : Int32, word : UInt32) -> Unit {
  let value = word.reinterpret_as_int()
  bytes[at] = (value & 0xFF).to_byte()
  bytes[at + 1] = ((value >> 8) & 0xFF).to_byte()
  bytes[at + 2] = ((value >> 16) & 0xFF).to_byte()
  bytes[at + 3] = ((value >> 24) & 0xFF).to_byte()
}

///|
/// Rotate left within thirty-two bits.
fn rotl(value : UInt32, by : Int32) -> UInt32 {
  ((value << by) | (value >> (32 - by))) & mask
}

///|
/// Salsa20/8 on the sixteen words at `from`, plus the input, written to `to`.
/// The addition at the end is what Salsa20 calls "plus" and what makes the
/// function invertible; the eight rounds are the "8".
fn salsa20_8(
  source : FixedArray[UInt32],
  from : Int32,
  to : FixedArray[UInt32],
  at : Int32,
) -> Unit {
  let mut x0 = source[from]
  let mut x1 = source[from + 1]
  let mut x2 = source[from + 2]
  let mut x3 = source[from + 3]
  let mut x4 = source[from + 4]
  let mut x5 = source[from + 5]
  let mut x6 = source[from + 6]
  let mut x7 = source[from + 7]
  let mut x8 = source[from + 8]
  let mut x9 = source[from + 9]
  let mut x10 = source[from + 10]
  let mut x11 = source[from + 11]
  let mut x12 = source[from + 12]
  let mut x13 = source[from + 13]
  let mut x14 = source[from + 14]
  let mut x15 = source[from + 15]
  for _ in 0..<4 {
    // Column round.
    x4 = x4 ^ rotl((x0 + x12) & mask, 7)
    x8 = x8 ^ rotl((x4 + x0) & mask, 9)
    x12 = x12 ^ rotl((x8 + x4) & mask, 13)
    x0 = x0 ^ rotl((x12 + x8) & mask, 18)
    x9 = x9 ^ rotl((x5 + x1) & mask, 7)
    x13 = x13 ^ rotl((x9 + x5) & mask, 9)
    x1 = x1 ^ rotl((x13 + x9) & mask, 13)
    x5 = x5 ^ rotl((x1 + x13) & mask, 18)
    x14 = x14 ^ rotl((x10 + x6) & mask, 7)
    x2 = x2 ^ rotl((x14 + x10) & mask, 9)
    x6 = x6 ^ rotl((x2 + x14) & mask, 13)
    x10 = x10 ^ rotl((x6 + x2) & mask, 18)
    x3 = x3 ^ rotl((x15 + x11) & mask, 7)
    x7 = x7 ^ rotl((x3 + x15) & mask, 9)
    x11 = x11 ^ rotl((x7 + x3) & mask, 13)
    x15 = x15 ^ rotl((x11 + x7) & mask, 18)
    // Row round.
    x1 = x1 ^ rotl((x0 + x3) & mask, 7)
    x2 = x2 ^ rotl((x1 + x0) & mask, 9)
    x3 = x3 ^ rotl((x2 + x1) & mask, 13)
    x0 = x0 ^ rotl((x3 + x2) & mask, 18)
    x6 = x6 ^ rotl((x5 + x4) & mask, 7)
    x7 = x7 ^ rotl((x6 + x5) & mask, 9)
    x4 = x4 ^ rotl((x7 + x6) & mask, 13)
    x5 = x5 ^ rotl((x4 + x7) & mask, 18)
    x11 = x11 ^ rotl((x10 + x9) & mask, 7)
    x8 = x8 ^ rotl((x11 + x10) & mask, 9)
    x9 = x9 ^ rotl((x8 + x11) & mask, 13)
    x10 = x10 ^ rotl((x9 + x8) & mask, 18)
    x12 = x12 ^ rotl((x15 + x14) & mask, 7)
    x13 = x13 ^ rotl((x12 + x15) & mask, 9)
    x14 = x14 ^ rotl((x13 + x12) & mask, 13)
    x15 = x15 ^ rotl((x14 + x13) & mask, 18)
  }
  let sum = FixedArray::make(16, 0U)
  sum[0] = x0
  sum[1] = x1
  sum[2] = x2
  sum[3] = x3
  sum[4] = x4
  sum[5] = x5
  sum[6] = x6
  sum[7] = x7
  sum[8] = x8
  sum[9] = x9
  sum[10] = x10
  sum[11] = x11
  sum[12] = x12
  sum[13] = x13
  sum[14] = x14
  sum[15] = x15
  for i in 0..<16 {
    to[at + i] = (sum[i] + source[from + i]) & mask
  }
}

///|
/// BlockMix, as RFC 7914 §5 defines it: the 2r blocks of `x` run through
/// Salsa20/8 one after another, each taking the previous result with it, and the
/// results are then dealt back out even blocks first, odd blocks second.
fn block_mix(
  x : FixedArray[UInt32],
  at : Int32,
  y : FixedArray[UInt32],
  r : Int32,
) -> Unit {
  let blocks = 2 * r
  let last = FixedArray::make(16, 0U)
  for i in 0..<16 {
    last[i] = x[at + (blocks - 1) * 16 + i]
  }
  for block in 0..<blocks {
    for i in 0..<16 {
      last[i] = last[i] ^ x[at + block * 16 + i]
    }
    salsa20_8(last, 0, y, block * 16)
    for i in 0..<16 {
      last[i] = y[block * 16 + i]
    }
  }
  for block in 0..<r {
    for i in 0..<16 {
      x[at + block * 16 + i] = y[2 * block * 16 + i]
    }
  }
  for block in 0..<r {
    for i in 0..<16 {
      x[at + (r + block) * 16 + i] = y[(2 * block + 1) * 16 + i]
    }
  }
}

///|
/// ROMix, as RFC 7914 §5 defines it: fill `n` copies of the block, each one
/// mixed from the last, then walk the same distance again, this time jumping to
/// wherever the block itself says — which is the part a machine cannot predict
/// or precompute.
fn romix(
  words : FixedArray[UInt32],
  at : Int32,
  scratch : FixedArray[UInt32],
  n : Int32,
  r : Int32,
) -> Unit {
  let block = 32 * r
  let x = FixedArray::make(block, 0U)
  let y = FixedArray::make(block, 0U)
  for i in 0..<block {
    x[i] = words[at + i]
  }
  for i in 0..<n {
    for k in 0..<block {
      scratch[i * block + k] = x[k]
    }
    block_mix(x, 0, y, r)
  }
  for _ in 0..<n {
    // Integerify: the first word of the last block, taken modulo n.
    let j = (x[(2 * r - 1) * 16] & (n - 1).reinterpret_as_uint()).reinterpret_as_int()
    for k in 0..<block {
      x[k] = x[k] ^ scratch[j * block + k]
    }
    block_mix(x, 0, y, r)
  }
  for i in 0..<block {
    words[at + i] = x[i]
  }
}
