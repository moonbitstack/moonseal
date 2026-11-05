// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The magic every `openssh-key-v1` file starts with, and the label its PEM
/// wrapper carries.
let openssh_magic : Bytes = b"openssh-key-v1\x00"

///|
let openssh_label : String = "OPENSSH PRIVATE KEY"

///|
/// `string` for a key type, then `string` for the key itself.
fn ed25519_blob(public : BytesView) -> Bytes {
  let out = @buffer.Buffer(size_hint=64)
  put_string(out, @utf8.encode(ed25519_kind))
  put_string(out, public)
  out.to_bytes()
}

///|
/// The RSA public key as SSH writes it: the type, the exponent, the modulus.
fn rsa_blob(exponent : BytesView, modulus : BytesView) -> Bytes {
  let out = @buffer.Buffer(size_hint=modulus.length() + exponent.length() + 16)
  put_string(out, @utf8.encode(rsa_kind))
  put_mpint(out, exponent)
  put_mpint(out, modulus)
  out.to_bytes()
}

///|
/// A secret key from the text of a key file: an OpenSSH private key, a PKCS#1
/// RSA key, or the PKCS#8 wrapper around one.
///
/// Whatever comment and options the file carries are ignored, and so is the
/// public key it repeats: the recipient is rebuilt from the secret, so the two
/// halves cannot disagree.
pub fn Identity::of(text : StringView) -> Self raise @spec.Refused {
  let (label, der) = @key.dearmor(text) catch {
    _ => raise @spec.Refused::Stanza(want="a PEM private key")
  }
  if label == openssh_label {
    return openssh_identity(der)
  }
  if label == "RSA PRIVATE KEY" {
    return rsa_identity(
      @key.parse_rsa_private(der) catch {
        _ => raise @spec.Refused::Stanza(want="a PKCS#1 RSA private key")
      },
    )
  }
  if label == "PRIVATE KEY" {
    let inner = @key.parse_pkcs8(der) catch {
      _ => raise @spec.Refused::Stanza(want="a PKCS#8 private key")
    }
    return rsa_identity(
      @key.parse_rsa_private(inner) catch {
        _ => raise @spec.Refused::Stanza(want="a PKCS#8 RSA private key")
      },
    )
  }
  raise @spec.Refused::Stanza(want="an OpenSSH, PKCS#1 or PKCS#8 private key")
}

///|
/// The OpenSSH container: a header naming the cipher and the key derivation,
/// then the public key, then the private half padded to the cipher's block.
///
/// Only the unencrypted form is read. Decrypting one means bcrypt_pbkdf and a
/// block cipher in counter mode, and the point of an SSH key here is that its
/// holder already has it — a passphrase on the file is a second lock on the same
/// door, and `ssh-keygen -p` removes it in one command.
fn openssh_identity(der : BytesView) -> Identity raise @spec.Refused {
  if der.length() < openssh_magic.length() ||
    !der.clamped_view(end=openssh_magic.length()).equal(openssh_magic) {
    raise @spec.Refused::Stanza(want="an openssh-key-v1 container")
  }
  let wire = Wire::new(der.clamped_view(start=openssh_magic.length()))
  let cipher = wire.text()
  let kdf = wire.text()
  ignore(wire.string())
  if cipher != "none" || kdf != "none" {
    raise @spec.Refused::Stanza(want="an unencrypted OpenSSH private key")
  }
  let count = wire.uint32()
  if count != 1 {
    raise @spec.Refused::Stanza(want="an OpenSSH file holding one key")
  }
  ignore(wire.string())
  let section = Wire::new(wire.string())
  let check = section.uint32()
  if check != section.uint32() {
    raise @spec.Refused::Stanza(
      want="an OpenSSH private key with one check word",
    )
  }
  let kind = section.text()
  if kind == ed25519_kind {
    let public = section.string()
    let secret = section.string()
    guard public.length() == 32 && secret.length() == 64 else {
      raise @spec.Refused::Stanza(want="a 32-byte Ed25519 key and its seed")
    }
    // The seed is the first half; the second is the public key again. Ed25519
    // turns the seed into a signing scalar by hashing it, and X25519 uses the
    // first half of that hash as its own scalar.
    let scalar = @sha2.hash(secret.clamped_view(end=32), kind=@sha2.Sha512).clamped_view(
      end=32,
    )
    let target = montgomery(public)
    return {
      kind: ed25519_kind,
      blob: ed25519_blob(public),
      secret: Secret::Ed25519(scalar=scalar.to_owned(), montgomery=target),
    }
  }
  if kind != rsa_kind {
    raise @spec.Refused::Stanza(want="an ssh-ed25519 or ssh-rsa private key")
  }
  let modulus = section.mpint()
  let exponent = section.mpint()
  let private_exponent = section.mpint()
  // The remaining three numbers are the Chinese-remainder halves; the key is
  // built from the exponent alone, as mooncrypt's RSA does everywhere.
  ignore(section.mpint())
  ignore(section.mpint())
  ignore(section.mpint())
  rsa_identity_of(modulus, exponent, private_exponent)
}

///|
/// A PKCS#1 key, as the DER parser hands it over.
fn rsa_identity(key : @key.RsaPrivate) -> Identity raise @spec.Refused {
  rsa_identity_of(
    key.modulus.to_octets(),
    key.public_exponent.to_octets(),
    key.private_exponent.to_octets(),
  )
}

///|
fn rsa_identity_of(
  modulus : BytesView,
  exponent : BytesView,
  private_exponent : BytesView,
) -> Identity raise @spec.Refused {
  if bits(modulus) < min_rsa_bits {
    raise @spec.Refused::Stanza(want="an RSA key of at least 2048 bits")
  }
  let key = @rsa.PrivateKey::new(modulus, exponent, private_exponent) catch {
    _ => raise @spec.Refused::Stanza(want="an RSA private key")
  }
  {
    kind: rsa_kind,
    blob: rsa_blob(exponent, modulus),
    secret: Secret::Rsa(key~, modulus=modulus.to_owned()),
  }
}
