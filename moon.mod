name = "moonbitstack/moonseal"

version = "0.1.4"

readme = "README.md"

repository = "https://github.com/moonbitstack/moonseal"

license = "Apache-2.0"

keywords = [
  "encryption",
  "file-encryption",
  "age",
  "age-encryption",
  "x25519",
  "scrypt",
  "passphrase",
  "recipients",
  "stanza",
  "armor",
  "stream",
  "chacha20-poly1305",
  "hkdf",
  "ssh",
  "ssh-ed25519",
  "ssh-rsa",
  "ed25519",
  "rsa",
  "rsa-oaep",
  "openssh",
  "authorized-keys",
  "post-quantum",
  "post-quantum-cryptography",
  "pqc",
  "ml-kem",
  "mlkem768",
  "x-wing",
  "hybrid",
  "hpke",
  "rfc9180",
  "p256",
  "p256tag",
  "mlkem768p256tag",
  "secp256r1",
  "nist-p256",
  "ecdh",
  "dhkem",
  "tag",
  "hardware-key",
  "security-key",
  "smart-card",
  "yubikey",
  "fips203",
  "rfc4253",
  "moonbit",
]

description = "File and message encryption for MoonBit, for one or several recipients."

source = "src"

import {
  "moonbitlang/x@0.5.1",
  "moonbitstack/mooncrypt@0.4.12",
  "moonbitstack/moonseed@0.1.1",
  "moonbitstack/moonbase@0.4.3",
}
