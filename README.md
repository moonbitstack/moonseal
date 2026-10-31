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

## Where the randomness comes from

From the caller. Every call that needs randomness takes `random`, a moonseed
`Source`: `@system.source` from `moonseed/system` in a program, or anything else
that implements the trait. A file draws in a fixed order: sixteen bytes for the
file key, then what each recipient type needs for its stanza (thirty-two for
X25519, sixteen for scrypt), then sixteen for the payload nonce. A source that
fails is a `Refused::Random`, raised before anything is written.

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

The MAC is HMAC-SHA-256 over the header up to and including its `---`, keyed
from the file key, which is why the header is verified before a single byte of
payload is decrypted: whoever can edit the list of stanzas can edit who reads the
file. The payload key is derived from the file key and the nonce, so two files
sealed under the same recipients differ from their first byte.

## What is deliberately elsewhere

| Thing | Why not here |
|:--|:--|
| Key storage, trust, rotation, revocation | All four need state, and a library with state is no longer a format. |
| A random-number generator | moonrand has them; the caller picks one and hands it in. |
| Certificates and tokens | Those assert who somebody is. This is a message, and asserts nothing. |

## Licence

Apache-2.0. See [LICENSE](LICENSE).
