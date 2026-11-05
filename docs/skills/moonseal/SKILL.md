---
name: moonseal
description: Seal a file or a message for one or several readers in the age format, and open it again. Use when a MoonBit program has to encrypt bytes to a public key, a passphrase, an SSH key, or a post-quantum hybrid key, or decrypt a file that another implementation produced.
---

# moonseal

A sealed file is a header of recipient stanzas over a streaming payload. Every
stanza wraps the same sixteen-byte file key, so a file addressed to four readers
is one file and any one of them opens it. The caller supplies the randomness and
owns the keys; the library keeps no state.

## Install

```bash
moon add moonbitstack/moonseal
moon add moonbitstack/moonseed
```

```moonbit
import {
  "moonbitstack/moonseal",
  "moonbitstack/moonseal/spec",
  "moonbitstack/moonseal/x25519",
  "moonbitstack/moonseed/system",
}
```

`@system.source` is the operating system's random source; every call that seals
takes one.

## Seal to a public key, open with the secret

```moonbit
let me = @x25519.Identity::generate(random=@system.source) catch {
  e => abort("no randomness: \{e}")
}
let recipients : Array[&@spec.Recipient] = [me.public()]
let file = @moonseal.seal(recipients, b"hello", random=@system.source) catch {
  e => abort("cannot seal: \{e}")
}
let readers : Array[&@spec.Identity] = [me]
let plain = @moonseal.open(readers, file) catch {
  e => abort("cannot open: \{e}")
}
println(plain)          // b"hello"
println(me.public().code())   // age1…
```

Keys written as text come back with `Identity::of` / `Recipient::of`. Use
`seal_armored` and `open_armored` when the result has to travel as text, and
`seal_stream` / `open_stream` when the file is bigger than memory.

## A passphrase, or an SSH key

```moonbit
let by_password = @moonseal.seal(
  [@scrypt.Recipient::new("correct horse battery staple", log_n=14)],
  b"hello",
  random=@system.source,
) catch {
  e => abort("cannot seal: \{e}")
```

An scrypt stanza must be alone in a header: a passphrase carries no identity, so
mixing it with a public key is refused rather than written.

```moonbit
let by_ssh = @moonseal.seal(
  [
    @ssh.Recipient::of(
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl someone@example",
    ),
  ],
  b"hello",
  random=@system.source,
) catch {
  e => abort("cannot seal: \{e}")
```

`@ssh.Identity::of(text)` reads an OpenSSH, PKCS#1 or PKCS#8 private key. Keys
strengthened with a passphrase are refused: run `ssh-keygen -p` on the file
first.

## Post-quantum

`@mlkem768x25519.Identity` is the hybrid X-Wing key: one 32-byte seed, written
`AGE-SECRET-KEY-PQ-1…`, whose recipient is `age1pq1…`. It is a recipient type
like any other.

Do not address one file to both a post-quantum recipient and an `age1…` one: the
file is then only as strong as the weaker stanza.

## Rules that bite

- `Recipient` and `Identity` are traits. Put values into
  `Array[&@spec.Recipient]` explicitly; an array literal of concrete types will
  not coerce on its own.
- The random source is an argument, never a global. Reuse one `Replay` only when
  you want the same file twice.
- `Refused::NoMatch` means no identity opened any stanza. A malformed stanza of
  a type the identity implements is a different error: the file is broken.
- Header bytes are authenticated before any payload is decrypted, so a
  `Refused::Mac` means the stanza list was edited; do not try the payload.
