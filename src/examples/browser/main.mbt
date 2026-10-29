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
fn words(text : String) -> Array[String] {
  text
  .split(" ")
  .flat_map(fn(w) { w.split(",") })
  .filter(fn(w) { !w.is_empty() })
  .map(fn(w) { w.to_owned() })
  .to_array()
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
/// `message` sealed to every `age1…` key in `keys`, as armor.
pub fn seal_to(keys : String, message : String) -> String {
  result(fn() raise @spec.Refused {
    let recipients : Array[&@spec.Recipient] = []
    for key in words(keys) {
      recipients.push(@x25519.Recipient::of(key))
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
/// `armored` opened with any of the `AGE-SECRET-KEY-1…` keys in `secrets`.
pub fn open_with(secrets : String, armored : String) -> String {
  result(fn() raise @spec.Refused {
    let identities : Array[&@spec.Identity] = []
    for key in words(secrets) {
      identities.push(@x25519.Identity::of(key))
    }
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
