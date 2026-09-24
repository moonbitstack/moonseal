# moonseal

Seal a file for several people at once; any one of them opens it.

> **Status: planned.** The repository is set up; nothing is
> implemented yet.

A header of recipient stanzas over a streaming payload. Each stanza carries the
payload key wrapped for one recipient, so a ciphertext addressed to four keys is
one ciphertext, not four. There is no key ring, no trust model and no key
server: where the keys come from is the caller's business.

| Package | What it does | Specification |
|:--|:--|:--|
| `header` | The stanzas, and the MAC that binds them to the payload | [age v1](https://age-encryption.org/v1) |
| `stream` | The payload: chunked AEAD, so a large file never has to be held whole | [age v1](https://age-encryption.org/v1) |
| `x25519` | The recipient type that wraps a key for a public key | [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) |
| `scrypt` | The recipient type that wraps a key for a passphrase | [RFC 7914](https://www.rfc-editor.org/rfc/rfc7914) |

## Why the format is somebody else's first

The first version implements [age](https://github.com/FiloSottile/age) v1 as
written, and adds its own recipient types on top of it afterwards — the format
reserves room for exactly that.

Not because that format is better than one we would design, but because **it
publishes test vectors and ours would not**. Every format library in this family
that came out right has an outside anchor behind it: `moontls` against
RFC 8448's traces, `moonschema` against the JSON Schema suite's 4950 cases,
`moonxml` against html5lib's. A format of our own invention would ship its first
version with nothing outside itself able to say it was right, which is the last
place to accept that.

## What is deliberately elsewhere

| Thing | Where it lives | Why |
|:--|:--|:--|
| The algorithms | [`mooncrypt`](https://github.com/moonbitstack/mooncrypt) | One algorithm to a package; this library composes them, it implements none |
| Recipient encoding | [`moonbase`](https://github.com/moonbitstack/moonbase) | Bech32 for the `age1…` form |
| JWT, JWK, X.509 | [`mooncred`](https://github.com/moonbitstack/mooncred) | Those are credentials — they assert who someone is. This is a message, and asserts nothing |
| Key storage, trust, rotation | nowhere — out of scope | All four need state, and a library with state is no longer a format |

## Install

```bash
moon add moonbitstack/moonseal
```

## Licence

Apache-2.0. See [LICENSE](LICENSE).
