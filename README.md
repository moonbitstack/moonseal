# moonseal

Seal a file for several people at once; any one of them opens it.

[Home and console](https://moonbitstack.github.io/moonseal/) · [API](https://moonbitstack.github.io/moonseal/#api) · [age v1](https://age-encryption.org/v1)

A sealed file is a header of recipient stanzas over a streaming payload. Each
stanza carries the same sixteen-byte file key, wrapped so that one reader can
unwrap it, and the payload is encrypted in chunks under a key derived from that
file key. A file addressed to four people is one file, not four, and any one of
those people opens it on their own.

There is no key ring, no trust model and no key server. Where keys come from,
and whether a public key belongs to the person it names, are the caller's
business — this library has no state to keep them in, and a format that kept
some would no longer be a format.

```moonbit
// Alice has a key pair; the public half is what a sender needs.
let alice = @x25519.Identity::generate(random=@system.source) catch {
  _ => abort("no randomness")
}
println(alice.code())          // AGE-SECRET-KEY-1…
println(alice.public().code()) // age1…

let recipients : Array[&@spec.Recipient] = [alice.public()]
let file = @moonseal.seal(recipients, b"the quick brown fox", random=@system.source) catch {
  _ => abort("cannot seal")
}

let readers : Array[&@spec.Identity] = [alice]
println(@moonseal.open(readers, file)) // b"the quick brown fox"
```

## Packages

| Package | What it does | Specification |
|:--|:--|:--|
| `moonseal` | Sealing and opening, in memory or as a stream, with or without an armor | [age v1](https://age-encryption.org/v1) |
| `spec` | The error type, the stanza, and the two traits a recipient type implements | |
| `header` | The stanzas and the MAC that binds them to the payload | [age v1](https://age-encryption.org/v1) |
| `stream` | The payload: chunks of 64 KiB, each authenticated on its own | [age v1](https://age-encryption.org/v1) |
| `armor` | The same file as text, when a binary cannot travel | [RFC 7468](https://www.rfc-editor.org/rfc/rfc7468) |
| `x25519` | A recipient type for a public key | [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) |
| `scrypt` | A recipient type for a passphrase | [RFC 7914](https://www.rfc-editor.org/rfc/rfc7914) |
| `ssh` | A recipient type for an SSH key the reader already has: `ssh-ed25519` and `ssh-rsa` | [RFC 4253](https://www.rfc-editor.org/rfc/rfc4253) |
| `mlkem768x25519` | A recipient type that survives a quantum computer: the hybrid X-Wing KEM under HPKE | [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) |
| `p256tag` | A recipient type for a key that lives in hardware: a P-256 point behind four bytes of tag | [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) |
| `mlkem768p256tag` | The same, for a key that also has to survive a quantum computer: ML-KEM-768 with P-256 | [C2SP age](https://c2sp.org/age) |

Import the ones you use. Nothing here is linked until something calls it.

## Install

<!-- nocheck -->

```bash
moon add moonbitstack/moonseal
moon add moonbitstack/moonseed
```

`@system` above is `moonbitstack/moonseed/system`, the operating system's random source.

## Use

### A passphrase instead of a key

A passphrase is a recipient type of its own, and it has to be alone in the
header: a file under one is a file whose only reader is whoever knows it, and
mixing it with a public key would let somebody be told a weaker story about who
else can read the file.

```moonbit
let file = @moonseal.seal(
  [@scrypt.Recipient::new("correct horse battery staple", log_n=14)],
  b"the quick brown fox",
  random=@system.source,
) catch {
  _ => abort("cannot seal")
}
let readers : Array[&@spec.Identity] = [
  @scrypt.Identity::new("correct horse battery staple"),
]
println(@moonseal.open(readers, file))
```

The work factor is the one knob that trades a reader's time for a guesser's.
Eighteen is the default; the format stops at twenty-two, which is four gibibytes
of scratch space, and a reader can set its own ceiling with `max_log_n`.

### A key the reader already has

An SSH key signs and does not encrypt, but the two halves still meet: an Ed25519
public key is a point that can be read as an X25519 one, and an RSA key can wrap
a file key under OAEP. So a file can be addressed to the key somebody already
has in `~/.ssh`, without them making anything new.

```moonbit
let reader = @ssh.Recipient::of(
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl someone@example",
) catch {
  _ => abort("not an SSH key")
}
let file = @moonseal.seal([reader], b"the quick brown fox", random=@system.source) catch {
  _ => abort("cannot seal")
}
```

The other side reads the private key file as it is: an OpenSSH key, or a PKCS#1
or PKCS#8 RSA key.

```moonbit
fn open_with_my_key(key_text : String, file : Bytes) -> Bytes raise {
  let identity : &@spec.Identity = @ssh.Identity::of(key_text)
  @moonseal.open([identity], file)
}
```

Both types carry a four-byte tag, the start of the SHA-256 of the public key as
SSH writes it, so a reader can skip the stanzas that are not worth a
decryption. The tag names a key, which is the price of that shortcut: unlike an
`age1…` recipient, an SSH one is not anonymous.

### For after the quantum computer

`mlkem768x25519` is the hybrid X-Wing KEM: an ML-KEM-768 secret and an X25519
secret, combined into one. Breaking either one alone leaves nothing to attack,
which is what makes a file sealed this way as safe after a quantum computer as
before it.

```moonbit
let after = @mlkem768x25519.Identity::generate(random=@system.source) catch {
  _ => abort("no randomness")
}
println(after.code())          // AGE-SECRET-KEY-PQ-1…
let file = @moonseal.seal([after.public()], b"still secret", random=@system.source) catch {
  _ => abort("cannot seal")
}
println(@moonseal.open([after], file))
```

A recipient is one seed; the ML-KEM key and the X25519 key are both expanded
from it, which is why the written form is one short string. A file addressed to
a post-quantum recipient should not also be addressed to an `age1…` one: the
file is then only as strong as the weaker stanza, and the header will happily
carry both.

### A key that lives in hardware

Some keys are not files. A smart card or a security token holds the secret and
will not let it out; it will decrypt, and only for somebody who is there to
touch it. A tagged recipient is how such a device is addressed: four bytes that
name the key, so that opening a file costs one prompt for the device it belongs
to rather than one per stanza in the header.

```moonbit
let device = @p256tag.Identity::generate(random=@system.source) catch {
  _ => abort("no randomness")
}
println(device.public().code()) // age1tag1…

let readers : Array[&@spec.Recipient] = [device.public()]
let file = @moonseal.seal(readers, b"for the key on the desk", random=@system.source) catch {
  _ => abort("cannot seal")
}
let holders : Array[&@spec.Identity] = [device]
println(@moonseal.open(holders, file))
```

The tag is a price as well as a shortcut. An `age1…` recipient is anonymous:
nobody holding a file can tell whether it was addressed to a given key. These
are not. Four bytes of the SHA-256 of the public key travel in every file
addressed to it, so anybody can tell which device a file was sealed for — which
is exactly what a device that must be asked needs to know, and exactly what a
reader who wanted anonymity should not use.

`mlkem768p256tag` (`age1tagpq1…`) is the same shape with an ML-KEM-768 key in
front of the curve: a file sealed to one needs both halves to open, so it stays
sealed against a quantum computer. The tag hashes the curve half alone, because
the ML-KEM half may be sealed inside the device and unreadable without it.

```moonbit
let after = @mlkem768p256tag.Identity::generate(random=@system.source) catch {
  _ => abort("no randomness")
}
println(after.public().code()) // age1tagpq1…
```

The format defines the recipient and not the identity, so there is no written
form for the secret half and no `code` on these two: what holds the key is
whatever the device's plugin is. `Identity::new` takes the thirty-two bytes such
a device would have, `Identity::from_seed` derives them from a seed the way HPKE
does, and `Identity::generate` draws them.

### A file larger than memory

`seal` and `open` take bytes and give bytes, which is what most callers want.
When the file is too large for that, the same format is available over a source
and a sink: a chunk is sealed, written and forgotten, and nothing bigger than one
chunk plus a header is ever held.

```moonbit
let sink = @moonseal.BytesSink::new()
@moonseal.seal_stream(
  sink,
  [@x25519.Recipient::of("age1…") catch { _ => abort("no") }],
  @moonseal.BytesSource::new(b"the quick brown fox"),
  random=@system.source,
) catch {
  _ => abort("cannot seal")
}
```

`BytesSource` and `BytesSink` are the in-memory pair; anything with a `read` and
a `write` can implement `Source` and `Sink` instead, which is how a file, a
socket or a pipe gets attached without this library knowing about any of them.

### Text instead of bytes

Somewhere along the way a file has to survive an email. `seal_armored` writes the
same file as a `-----BEGIN AGE ENCRYPTED FILE-----` block, and `open_armored`
reads it back; the streaming forms do the same without holding the text either.

```moonbit
let text = @moonseal.seal_armored(
  [@x25519.Recipient::of("age1…") catch { _ => abort("no") }],
  b"the quick brown fox",
  random=@system.source,
) catch {
  _ => abort("cannot seal")
}
println(text)
```

Reading is stricter than writing, on purpose. Whitespace around the block and
either line ending are allowed, because mail clients add one and platforms
disagree about the other. Nothing inside is: a line that is not sixty-four
columns, a block whose length is not a multiple of four after padding, or a
second copy of the same bytes are all refusals, because a second spelling of one
file is a second file to everybody downstream.

### A recipient type of your own

The header carries stanzas it does not understand, which is what leaves room for
a type this library has never heard of. Implement two methods and a file can be
addressed to it:

```moonbit
struct Example {}

impl @spec.Recipient for Example with fn wrap(self, file_key~, random~) {
  ignore(self)
  ignore(random)
  // The body is whatever the matching identity can unwrap. This one hands the
  // file key over as it is, which is not a design to use; a real type draws
  // its ephemeral material with `@spec.draw(random, len)`.
  @spec.Stanza::new(kind="example.com/plain", args=[], body=file_key.to_owned())
}

impl @spec.Identity for Example with fn unwrap(self, stanza~) {
  ignore(self)
  if stanza.kind == "example.com/plain" {
    return Some(stanza.body)
  }
  None
}
```

`None` means "not mine, try the next stanza", and it is the answer for a type
this identity does not implement as well as for one that is addressed to somebody
else. A stanza that claims to be this type and is malformed is a refusal instead,
because at that point the file is broken rather than somebody else's.

## The interface

### `moonseal`

| | |
|:--|:--|
| `seal(recipients, plain, random~) -> Bytes` | Seal bytes for a list of recipients. |
| `open(identities, cipher) -> Bytes` | Open a file with any one of these identities. |
| `seal_armored(recipients, plain, random~) -> String` | The same file, as text. |
| `open_armored(identities, text) -> Bytes` | Open an armored block. |
| `seal_stream(sink, recipients, source, random~)` | Seal from a source into a sink. |
| `open_stream(sink, identities, source)` | Open from a source into a sink. |
| `seal_stream_armored(sink, recipients, source, random~)` | The same, as text. |
| `open_stream_armored(sink, identities, source)` | The same, as text. |
| `drain(source) -> Bytes` | Everything a source has. |
| `BytesSource::new(BytesView)` / `BytesSink::new()` / `BytesSink::bytes()` | The in-memory pair. |
| `Source::read(limit~)` / `Sink::write(bytes~)` | What a caller implements to attach a file, a socket or a pipe. |

### `spec`

| | |
|:--|:--|
| `Refused` | Why a call did not do what it was asked: a header that is not the format, a stanza of a known type that is not either, a MAC that does not verify, no identity that opens anything, a chunk that does not authenticate, armor that is not armor, a key of the wrong size, a random source that failed, an input past a limit. |
| `Stanza { kind, args, body }` | One recipient stanza, as the header carries it. |
| `draw(random, len) -> Bytes` | Bytes from a random source, with its failure as a `Refused`. |
| `Recipient::wrap(self, file_key~, random~) -> Stanza` | What a recipient type implements to address a file. |
| `Identity::unwrap(self, stanza~) -> Bytes?` | What it implements to open one. |

### `header`, `stream`, `armor`

| | |
|:--|:--|
| `Header::decode(bytes) -> (Header, Int)` | Read a header, and say where the payload starts. |
| `Header::encode(file_key~) -> Bytes` | Write it, MAC line and all. |
| `Header::new(stanzas)` / `verify(file_key~)` | Build one; check the MAC of one that was read. |
| `Header::stanzas()` | The stanzas, in the order they are written. |
| `stream.chunk` / `stream.tag` / `stream.nonce` | 64 KiB, 16 bytes, 16 bytes. |
| `stream.payload_key(file_key~, nonce~)` | The payload key for one file. |
| `Sealer::chunk(plain~, last~)` / `Opener::chunk(cipher~, last~)` | One chunk at a time, for callers building their own plumbing. |
| `armor.encode(bytes)` / `armor.decode(text)` | The text form. |
| `armor.Encoder` / `armor.Decoder` | The same a piece at a time. |

### `x25519`, `scrypt`

| | |
|:--|:--|
| `x25519.Identity::generate(random~)` / `Identity::new(scalar)` | A secret key, from randomness or from bytes. |
| `x25519.Identity::of(text)` / `code()` | `AGE-SECRET-KEY-1…` in and out. |
| `x25519.Identity::public()` / `Recipient::of(text)` / `Recipient::code()` | `age1…` in and out. |
| `scrypt.Recipient::new(passphrase, log_n?)` / `scrypt.Identity::new(passphrase, max_log_n?)` | A passphrase, with the work factor to write and the one to accept. |

### `ssh`, `mlkem768x25519`

| | |
|:--|:--|
| `ssh.Recipient::of(line)` | The key half of an `authorized_keys` line. |
| `ssh.Recipient::new(blob)` | The same key as SSH writes it on the wire. |
| `ssh.Recipient::kind()` / `code()` / `fingerprint()` / `blob()` | `ssh-ed25519` or `ssh-rsa`; the line back; the four-byte tag; the wire key. |
| `ssh.Identity::of(text)` | An OpenSSH, PKCS#1 or PKCS#8 private key, as text. |
| `ssh.Identity::public()` / `kind()` / `blob()` | What a sender needs from it. |
| `ssh.min_rsa_bits` | 2048: below it a modulus is a file that looks safer than it is. |
| `mlkem768x25519.Identity::generate(random~)` / `Identity::new(seed)` | A 32-byte seed that expands into both halves. |
| `mlkem768x25519.Identity::of(text)` / `code()` | `AGE-SECRET-KEY-PQ-1…` in and out. |
| `mlkem768x25519.Identity::public()` / `Recipient::of(text)` / `Recipient::code()` | `age1pq1…` in and out. |
| `mlkem768x25519.Recipient::key()` / `size` | The 1216-byte key, and the seed length. |

### `p256tag`, `mlkem768p256tag`

| | |
|:--|:--|
| `p256tag.Recipient::of(text)` / `Recipient::new(point)` | `age1tag1…`, or the thirty-three bytes of a compressed point. |
| `p256tag.Recipient::code()` / `key()` / `tag(enc)` | The written form; the point back; the four bytes that name it in a stanza. |
| `p256tag.Identity::new(scalar)` / `Identity::generate(random~)` / `Identity::from_seed(seed)` | A secret, from bytes, from randomness, or derived from a seed. |
| `p256tag.Identity::public()` / `key()` | What a sender needs; the scalar back. |
| `p256tag.point_size` / `size` | 33 bytes of point; 32 bytes of scalar. |
| `mlkem768p256tag.Recipient::of(text)` / `Recipient::new(key)` / `code()` / `key()` | `age1tagpq1…` in and out. |
| `mlkem768p256tag.Recipient::tag(enc)` | The four bytes that name it, hashed from the curve half. |
| `mlkem768p256tag.Identity::new(seed)` / `generate(random~)` / `from_seed(seed)` | A secret: one seed both halves expand from. |
| `mlkem768p256tag.Identity::public()` / `key()` | What a sender needs; the seed back. |
| `mlkem768p256tag.public_size` / `size` | 1249 bytes of public key; 32 bytes of seed. |

## Where the randomness comes from

From the caller. Every call that needs randomness takes `random`, a moonseed
`Source`: `@system.source` from `moonseed/system` in a program, or anything else
that implements the trait. A file draws in a fixed order: sixteen bytes for the
file key, then what each recipient type needs for its stanza, then sixteen for
the payload nonce. A recipient type takes thirty-two bytes for X25519, sixteen
for scrypt, thirty-two for `ssh-ed25519`, thirty-two for the OAEP seed of
`ssh-rsa`, sixty-four for `mlkem768x25519` — a thirty-two-byte ML-KEM message and
an X25519 scalar — thirty-two for `p256tag`, and sixty-four for
`mlkem768p256tag`, the same message and a P-256 scalar. A source that fails is a `Refused::Random`, raised before
anything is written.

The fixed order makes sealing reproducible: the same plaintext, the same
recipients and a `Replay` of the same bytes give the same file, byte for byte,
which is what the test suite uses to pin the format.

## What a file looks like

```
age-encryption.org/v1
-> X25519 aQwdcB4/zsAqbGhOXDVcZMGvC5J5bTdhqqZyiK6V9l0
n3ccxIiZEos8us5SboQVs0swdWU9NV2gbGJgYKAu+Xk
--- A7bGuYb5XUntlaP2+ePJxehnm4uFu1f3Loora2+eEmg
<16-byte nonce><chunks of 64 KiB, each with a 16-byte tag>
```

A file addressed to a key in hardware carries the tag as the stanza's first
argument, and the encapsulation after it:

```
age-encryption.org/v1
-> p256tag PLEV1w BMLux/5FwmdV/lxfPBeEUsukUDz41eCLuBEtzUyzErnGzKO+DQUUefmZ7gjEUnb1cj0oeienTxXMfkB1E7YH6b8
g1LChJKvHebotrXZPy6J45A5vz9jHsdfd43fJTqlkqQ
```

The MAC is HMAC-SHA-256 over the header up to and including its `---`, keyed
from the file key, which is why the header is verified before a single byte of
payload is decrypted: whoever can edit the list of stanzas can edit who reads the
file. The payload key is derived from the file key and the nonce, so two files
sealed under the same recipients differ from their first byte.

## What is deliberately elsewhere

| Thing | Why not here |
|:--|:--|
| Key storage, trust, rotation, revocation | All four need state, and a library with state is no longer a format. |
| Decrypting a passphrase-protected SSH key | `ssh-keygen -p` removes the passphrase, and the point of an SSH key here is that its holder already has it. |
| A random-number generator | moonrand has them; the caller picks one and hands it in. |
| A written form for a tagged identity | The format defines none: the secret is in a token, and naming it is the plugin's business. |
| Certificates and tokens | Those assert who somebody is. This is a message, and asserts nothing. |

## Licence

Apache-2.0. See [LICENSE](LICENSE).
