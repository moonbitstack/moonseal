// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The passphrase prefix a recipients or identity file may use, so that one file
/// format covers every kind of reader this library has.
let passphrase_prefix : String = "passphrase:"

///|
/// The work factor this tool writes for a passphrase. It is low because the
/// files here live for the length of a test, and because the other
/// implementations it talks to accept whatever number a file asks for.
let work_factor : Int32 = 10

///|
/// One recipient, from the line that names it.
fn recipient_of(line : String) -> &@spec.Recipient raise @spec.Refused {
  if line.has_prefix(passphrase_prefix) {
    let recipient : &@spec.Recipient = @scrypt.Recipient::new(
      line.clamped_view(start=passphrase_prefix.length()).to_owned(),
      log_n=work_factor,
    )
    return recipient
  }
  if line.has_prefix("ssh-") {
    let recipient : &@spec.Recipient = @ssh.Recipient::of(line)
    return recipient
  }
  if line.has_prefix("age1pq1") {
    let recipient : &@spec.Recipient = @mlkem768x25519.Recipient::of(line)
    return recipient
  }
  let recipient : &@spec.Recipient = @x25519.Recipient::of(line)
  recipient
}

///|
/// One identity, from the text of a file.
fn identity_of(text : String) -> &@spec.Identity raise @spec.Refused {
  if text.has_prefix(passphrase_prefix) {
    let identity : &@spec.Identity = @scrypt.Identity::new(
      text.clamped_view(start=passphrase_prefix.length()).to_owned(),
    )
    return identity
  }
  if text.has_prefix("AGE-SECRET-KEY-PQ-") {
    let identity : &@spec.Identity = @mlkem768x25519.Identity::of(text)
    return identity
  }
  if text.has_prefix("AGE-SECRET-KEY-") {
    let identity : &@spec.Identity = @x25519.Identity::of(text)
    return identity
  }
  let identity : &@spec.Identity = @ssh.Identity::of(text)
  identity
}

///|
/// The public half of an identity, written the way a recipient file writes one.
fn recipient_line(text : String) -> String raise @spec.Refused {
  if text.has_prefix("AGE-SECRET-KEY-PQ-") {
    return @mlkem768x25519.Identity::of(text).public().code()
  }
  if text.has_prefix("AGE-SECRET-KEY-") {
    return @x25519.Identity::of(text).public().code()
  }
  @ssh.Identity::of(text).public().code()
}

///|
/// A file's text, with the line ending a file picked up on the way removed from
/// its end.
fn read_text(path : String) -> String raise {
  @fs.read_file_to_string(path).trim_end().to_owned()
}

///|
/// An identity file's text, without the comment lines a key generator writes
/// above the key.
fn identity_text(path : String) -> String raise {
  let kept = []
  for line in read_text(path).split("\n") {
    if !line.has_prefix("#") {
      kept.push(line)
    }
  }
  kept.join("\n").trim().to_owned()
}

///|
/// The lines of a recipients file that say something.
fn lines_of(text : String) -> Array[String] {
  let lines = []
  for line in text.split("\n") {
    let line = line.trim().to_owned()
    if line.length() > 0 && !line.has_prefix("#") {
      lines.push(line)
    }
  }
  lines
}

///|
fn seal(args : Array[String]) -> Unit raise {
  guard args.length() == 3 else {
    raise @spec.Refused::Limit(want=3, got=args.length())
  }
  let plain = @fs.read_file_to_bytes(args[0])
  let recipients = []
  for line in lines_of(read_text(args[2])) {
    recipients.push(recipient_of(line))
  }
  let file = @moonseal.seal(recipients, plain, random=@system.source)
  @fs.write_bytes_to_file(args[1], file)
  println(
    "sealed \{plain.length()} bytes to \{recipients.length()} recipient(s)",
  )
}

///|
fn open(args : Array[String]) -> Unit raise {
  guard args.length() >= 3 else {
    raise @spec.Refused::Limit(want=3, got=args.length())
  }
  let file = @fs.read_file_to_bytes(args[0])
  let identities = []
  for path in args[2:] {
    identities.push(identity_of(identity_text(path)))
  }
  let plain = @moonseal.open(identities, file)
  @fs.write_bytes_to_file(args[1], plain)
  println("opened \{plain.length()} bytes")
}

///|
fn dispatch(rest : Array[String]) -> Unit raise {
  match rest[0] {
    "seal" => seal(rest[1:].to_owned())
    "open" => open(rest[1:].to_owned())
    "recipient" => {
      guard rest.length() == 2 else {
        raise @spec.Refused::Limit(want=1, got=rest.length() - 1)
      }
      println(recipient_line(identity_text(rest[1])))
    }
    _ => {
      println("interop: unknown command \{rest[0]}")
      @env.exit(2)
    }
  }
}

///|
fn main {
  let args = @env.args()
  if args.length() < 2 {
    println(
      "interop: seal <in> <out> <recipients> | open <in> <out> <identity>... | recipient <identity>",
    )
    return
  }
  let outcome = try {
    dispatch(args[1:].to_owned())
    None
  } catch {
    error => Some(error)
  }
  match outcome {
    Some(error) => {
      println("interop: \{error}")
      @env.exit(1)
    }
    None => ()
  }
}
