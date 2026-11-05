name = "moonbitstack/moonseal"

version = "0.1.3"

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
  "moonbit",
]

description = "File and message encryption for MoonBit, for one or several recipients."

source = "src"

import {
  "moonbitlang/x@0.5.1",
  "moonbitstack/mooncrypt@0.4.11",
  "moonbitstack/moonseed@0.1.1",
  "moonbitstack/moonbase@0.4.3",
}
