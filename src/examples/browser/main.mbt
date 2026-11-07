// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn result(run : () -> Json raise @spec.Refused) -> String {
  let json : Json = { "ok": true, "value": run() } catch {
    e => { "ok": false, "error": Json::string(e.to_string()) }
  }
  json.stringify()
}

///|
/// The keys a line of text names, split on spaces and commas.
///
/// An SSH key is two words — the type and the key — so a pair that starts with
/// one is put back together; a comment after it is left as the separate word it
/// is, and the console trims it before calling.
fn words(text : String) -> Array[String] {
  let parts = text
    .split(" ")
    .flat_map(fn(w) { w.split(",") })
    .filter(fn(w) { !w.is_empty() })
    .map(fn(w) { w.to_owned() })
    .to_array()
  let out : Array[String] = []
  let mut at = 0
  while at < parts.length() {
    let word = parts[at]
    if (word == "ssh-ed25519" || word == "ssh-rsa") && at + 1 < parts.length() {
      out.push(word + " " + parts[at + 1])
      at = at + 2
    } else {
      out.push(word)
      at = at + 1
    }
  }
  out
}

///|
fn text(bytes : Bytes) -> Json {
  Json::string(@utf8.decode_lossy(bytes))
}

///|
/// A fresh X25519 identity from the browser's random source.
pub fn keygen() -> String {
  result(fn() raise @spec.Refused {
    let me = @x25519.Identity::generate(random=@system.source)
    {
      "secret": Json::string(me.code()),
      "public": Json::string(me.public().code()),
    }
  })
}

///|
/// A fresh post-quantum identity: one seed that expands into both halves.
pub fn keygen_pq() -> String {
  result(fn() raise @spec.Refused {
    let me = @mlkem768x25519.Identity::generate(random=@system.source)
    {
      "secret": Json::string(me.code()),
      "public": Json::string(me.public().code()),
    }
  })
}

///|
/// A fresh tagged identity: the scalar a device would hold, in hex, and the
/// recipient a sender writes.
pub fn keygen_tag() -> String {
  result(fn() raise @spec.Refused {
    let me = @p256tag.Identity::generate(random=@system.source)
    {
      "secret": Json::string(@base16.encode(me.key())),
      "public": Json::string(me.public().code()),
    }
  })
}

///|
/// The same for the hybrid tagged type, whose secret is one seed.
pub fn keygen_tag_pq() -> String {
  result(fn() raise @spec.Refused {
    let me = @mlkem768p256tag.Identity::generate(random=@system.source)
    {
      "secret": Json::string(@base16.encode(me.key())),
      "public": Json::string(me.public().code()),
    }
  })
}

///|
/// `message` sealed to a passphrase at work factor `log_n`, as armor.
pub fn seal_passphrase(
  passphrase : String,
  message : String,
  log_n : Int32,
) -> String {
  result(fn() raise @spec.Refused {
    let recipients : Array[&@spec.Recipient] = [
      @scrypt.Recipient::new(passphrase, log_n~),
    ]
    let file = @moonseal.seal_armored(
      recipients,
      @utf8.encode(message),
      random=@system.source,
    )
    Json::string(file)
  })
}

///|
/// The recipient a written key names: `age1…`, `age1pq1…`, or the key half of an
/// `authorized_keys` line.
fn recipient_of(key : String) -> &@spec.Recipient raise @spec.Refused {
  if key.has_prefix("ssh-") {
    let recipient : &@spec.Recipient = @ssh.Recipient::of(key)
    return recipient
  }
  if key.has_prefix("age1tagpq1") {
    let recipient : &@spec.Recipient = @mlkem768p256tag.Recipient::of(key)
    return recipient
  }
  if key.has_prefix("age1tag1") {
    let recipient : &@spec.Recipient = @p256tag.Recipient::of(key)
    return recipient
  }
  if key.has_prefix("age1pq1") {
    let recipient : &@spec.Recipient = @mlkem768x25519.Recipient::of(key)
    return recipient
  }
  let recipient : &@spec.Recipient = @x25519.Recipient::of(key)
  recipient
}

///|
/// `message` sealed to every key in `keys`, as armor.
pub fn seal_to(keys : String, message : String) -> String {
  result(fn() raise @spec.Refused {
    let recipients : Array[&@spec.Recipient] = []
    for key in words(keys) {
      recipients.push(recipient_of(key))
    }
    let file = @moonseal.seal_armored(
      recipients,
      @utf8.encode(message),
      random=@system.source,
    )
    Json::string(file)
  })
}

///|
pub fn open_passphrase(passphrase : String, armored : String) -> String {
  result(fn() raise @spec.Refused {
    let identities : Array[&@spec.Identity] = [
      @scrypt.Identity::new(passphrase),
    ]
    text(@moonseal.open_armored(identities, armored))
  })
}

///|
/// `armored` opened with any of the `AGE-SECRET-KEY-1…` or
/// `AGE-SECRET-KEY-PQ-1…` keys in `secrets`.
pub fn open_with(secrets : String, armored : String) -> String {
  result(fn() raise @spec.Refused {
    let identities : Array[&@spec.Identity] = []
    for key in words(secrets) {
      if key.has_prefix("AGE-SECRET-KEY-PQ-") {
        let identity : &@spec.Identity = @mlkem768x25519.Identity::of(key)
        identities.push(identity)
      } else {
        let identity : &@spec.Identity = @x25519.Identity::of(key)
        identities.push(identity)
      }
    }
    text(@moonseal.open_armored(identities, armored))
  })
}

///|
/// `armored` opened with a tagged identity, written as the hex of its scalar.
pub fn open_tag(secret : String, armored : String) -> String {
  result(fn() raise @spec.Refused {
    let scalar = @base16.decode(secret) catch {
      _ => raise @spec.Refused::Stanza(want="a hex scalar")
    }
    let identity : &@spec.Identity = @p256tag.Identity::new(scalar)
    let identities : Array[&@spec.Identity] = [identity]
    text(@moonseal.open_armored(identities, armored))
  })
}

///|
/// The same, with the seed the hybrid tagged identity is made of.
pub fn open_tag_pq(seed : String, armored : String) -> String {
  result(fn() raise @spec.Refused {
    let material = @base16.decode(seed) catch {
      _ => raise @spec.Refused::Stanza(want="a hex seed")
    }
    let identity : &@spec.Identity = @mlkem768p256tag.Identity::new(material)
    let identities : Array[&@spec.Identity] = [identity]
    text(@moonseal.open_armored(identities, armored))
  })
}

///|
/// What the header of an armored file says, and how long its payload is.
pub fn inspect(armored : String) -> String {
  result(fn() raise @spec.Refused {
    let bytes = @armor.decode(armored)
    let (head, at) = @header.Header::decode(bytes)
    let stanzas : Array[Json] = head
      .stanzas()
      .map(fn(s) {
        {
          "kind": Json::string(s.kind),
          "args": Json::array(s.args.map(Json::string)),
          "body": Json::number(s.body.length().to_double()),
        }
      })
    {
      "header": text(bytes[:at].to_owned()),
      "stanzas": Json::array(stanzas),
      "payload": Json::number((bytes.length() - at).to_double()),
      "bytes": Json::number(bytes.length().to_double()),
    }
  })
}
