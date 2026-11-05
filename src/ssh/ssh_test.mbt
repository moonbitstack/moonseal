// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Keys made once with `ssh-keygen` for these tests and for nothing else: an
/// Ed25519 key, a 2048-bit RSA key in the three formats a key file comes in, and
/// a 1024-bit key that the library is supposed to refuse.
let ed25519_private : String = "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
  "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" +
  "QyNTUxOQAAACCj1NPYOXqeqx5bW9IoIA8woXWUY0Vg9EQQKdjNlC3bPQAAAJhu61QLbutU\n" +
  "CwAAAAtzc2gtZWQyNTUxOQAAACCj1NPYOXqeqx5bW9IoIA8woXWUY0Vg9EQQKdjNlC3bPQ\n" +
  "AAAEAukeJxDZQaV4aX2WXS04S8Wug7ocLJMAITrzAPN8uzhaPU09g5ep6rHltb0iggDzCh\n" +
  "dZRjRWD0RBAp2M2ULds9AAAAFW1vb25zZWFsIHRlc3QgZWQyNTUxOQ==\n" +
  "-----END OPENSSH PRIVATE KEY-----"

///|
let ed25519_public : String = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKPU09g5ep6rHltb0iggDzChdZRjRWD0RBAp2M2ULds9"

///|
let rsa_private : String = "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
  "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\n" +
  "NhAAAAAwEAAQAAAQEAnxd7r8CA/NTkYeEsUQ/OTOynZm7n6kWKVeds10pUuy1oiugvDxfd\n" +
  "L4Wk9pt4gmeBqHKci7oD1zkeICbL21LeHDo9+JbaAz+Wjcm2CxkZtyoMyuvFtOx2h8mZJz\n" +
  "fe1Ujf5iWNqr513Tb361gTk9a55Efkj/LqbxsID9/uiJqqsiMDtLLowdhGJETmXHvuzTz5\n" +
  "J4rDxk4IQw1MJX75q1UtToaWEAB1Dlt9o90OGh/A50t0rjeTfXiFgnrM4Ss2k00U6Bnfri\n" +
  "cDTJH0y++ChtAKbc5hEyI6UY4mZO0/8TqAmBHD6mr/j8OxFikfmGPvePdHpFmk/MwiZGsd\n" +
  "gyDFjqBGhQAAA8hrDaVtaw2lbQAAAAdzc2gtcnNhAAABAQCfF3uvwID81ORh4SxRD85M7K\n" +
  "dmbufqRYpV52zXSlS7LWiK6C8PF90vhaT2m3iCZ4GocpyLugPXOR4gJsvbUt4cOj34ltoD\n" +
  "P5aNybYLGRm3KgzK68W07HaHyZknN97VSN/mJY2qvnXdNvfrWBOT1rnkR+SP8upvGwgP3+\n" +
  "6ImqqyIwO0sujB2EYkROZce+7NPPknisPGTghDDUwlfvmrVS1OhpYQAHUOW32j3Q4aH8Dn\n" +
  "S3SuN5N9eIWCeszhKzaTTRToGd+uJwNMkfTL74KG0AptzmETIjpRjiZk7T/xOoCYEcPqav\n" +
  "+Pw7EWKR+YY+9490ekWaT8zCJkax2DIMWOoEaFAAAAAwEAAQAAAQAHs4bQxLRZyOJ/XHud\n" +
  "NvMpJSGbY04FuLUQIIJTz6zXXMTdSI0SoXibFtCcAX2tbl5H7bhnSStrbT/olYgzx0iqPC\n" +
  "WI1aCbHKZombWexunIRJhW8F/jOLkqLJel3t4CHCN+jB3WAJ9LBKCuu1ZDR1c7VkGZuEwh\n" +
  "8cCLqC7vXPFbayPrAdKvWkyZvsMv6xSNNyue0CZQYskJ6ybzu9XlNXk/2AppocyEXo1Ayv\n" +
  "UaiE5nHOeNwhSN4Hb+V7Nt9+XFfwZO1aulLXPMtLQmKAA1KyRSG4jDL+Ioh11hQQmo0QO1\n" +
  "L1JyPyop1Yv/GKkMGV0pSUfdcsJL1LbQaBOy+tYwScCxAAAAgQCOcr8gIzQDqTZiGVuotI\n" +
  "c2IrPSMAApWIVZD86MLQ5wTPovMPRUd5OzWAHsIMrR2pfHviioOgYu8y04WmPHFqGqhkbR\n" +
  "IxddalefJdjMR0Ud/uLMij+nh3pAV/ApuRzW0YDdL/otly27nvTbGHDhXPA+FPMz3q6W1C\n" +
  "tTypFnb+Kt8AAAAIEA1+LLGhwmii248tph3+hLAYf+Is3AZcXUQ2/n0mxX/u8SX+1odwWc\n" +
  "ARc1jAKsVWYpmuqMVhp7dCSvDmyGoP8CeL3LTWnRhmWSA64VW/rNKNBXjL8vZq0tCbTola\n" +
  "fJENneEbVb2Taskz2AiE2UduVfvvyIZTkcX2J7zbZJR7LF6T0AAACBALynHlcqmQFlbjib\n" +
  "ifuBB11CC06pJJPyqB53Jp2o/YwxmL6x42NpdBvkJj7f8OdLcj+LxyJwQtZ5x+OZ7+7BDW\n" +
  "t6ZZxn/hlGBBv55CCP2zipyBkkPzcvQDyh8aDl2nUDJu+cA9wmhNVAQZ1SxBJ8uFLQhGi/\n" +
  "2lDbX0PvAzbB/tbpAAAAEW1vb25zZWFsIHRlc3QgcnNhAQ==\n" +
  "-----END OPENSSH PRIVATE KEY-----"

///|
let rsa_public : String = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCfF3uvwID81ORh4SxRD85M7KdmbufqRYpV52zXSlS7LWiK6C8PF90vhaT2m3iCZ4GocpyLugPXOR4gJsvbUt4cOj34ltoDP5aNybYLGRm3KgzK68W07HaHyZknN97VSN/mJY2qvnXdNvfrWBOT1rnkR+SP8upvGwgP3+6ImqqyIwO0sujB2EYkROZce+7NPPknisPGTghDDUwlfvmrVS1OhpYQAHUOW32j3Q4aH8DnS3SuN5N9eIWCeszhKzaTTRToGd+uJwNMkfTL74KG0AptzmETIjpRjiZk7T/xOoCYEcPqav+Pw7EWKR+YY+9490ekWaT8zCJkax2DIMWOoEaF"

///|
let rsa_pkcs1 : String = "-----BEGIN RSA PRIVATE KEY-----\n" +
  "MIIEpAIBAAKCAQEAnxd7r8CA/NTkYeEsUQ/OTOynZm7n6kWKVeds10pUuy1oiugv\n" +
  "DxfdL4Wk9pt4gmeBqHKci7oD1zkeICbL21LeHDo9+JbaAz+Wjcm2CxkZtyoMyuvF\n" +
  "tOx2h8mZJzfe1Ujf5iWNqr513Tb361gTk9a55Efkj/LqbxsID9/uiJqqsiMDtLLo\n" +
  "wdhGJETmXHvuzTz5J4rDxk4IQw1MJX75q1UtToaWEAB1Dlt9o90OGh/A50t0rjeT\n" +
  "fXiFgnrM4Ss2k00U6BnfricDTJH0y++ChtAKbc5hEyI6UY4mZO0/8TqAmBHD6mr/\n" +
  "j8OxFikfmGPvePdHpFmk/MwiZGsdgyDFjqBGhQIDAQABAoIBAAezhtDEtFnI4n9c\n" +
  "e5028yklIZtjTgW4tRAgglPPrNdcxN1IjRKheJsW0JwBfa1uXkftuGdJK2ttP+iV\n" +
  "iDPHSKo8JYjVoJscpmiZtZ7G6chEmFbwX+M4uSosl6Xe3gIcI36MHdYAn0sEoK67\n" +
  "VkNHVztWQZm4TCHxwIuoLu9c8VtrI+sB0q9aTJm+wy/rFI03K57QJlBiyQnrJvO7\n" +
  "1eU1eT/YCmmhzIRejUDK9RqITmcc543CFI3gdv5Xs2335cV/Bk7Vq6Utc8y0tCYo\n" +
  "ADUrJFIbiMMv4iiHXWFBCajRA7UvUnI/KinVi/8YqQwZXSlJR91ywkvUttBoE7L6\n" +
  "1jBJwLECgYEA1+LLGhwmii248tph3+hLAYf+Is3AZcXUQ2/n0mxX/u8SX+1odwWc\n" +
  "ARc1jAKsVWYpmuqMVhp7dCSvDmyGoP8CeL3LTWnRhmWSA64VW/rNKNBXjL8vZq0t\n" +
  "CbTolafJENneEbVb2Taskz2AiE2UduVfvvyIZTkcX2J7zbZJR7LF6T0CgYEAvKce\n" +
  "VyqZAWVuOJuJ+4EHXUILTqkkk/KoHncmnaj9jDGYvrHjY2l0G+QmPt/w50tyP4vH\n" +
  "InBC1nnH45nv7sENa3plnGf+GUYEG/nkII/bOKnIGSQ/Ny9APKHxoOXadQMm75wD\n" +
  "3CaE1UBBnVLEEny4UtCEaL/aUNtfQ+8DNsH+1ukCgYEAmuYYUmimYnjB/kYg+dYj\n" +
  "kzqvZut4Q825KpXtoPaqALoq1fdzAAtfTw0HF6mHW1MNQSFPhixELiZwEIpf4r52\n" +
  "WIndiHMHqkXQiaFro+6FK+apGszGxwY0jYVnaJHV26hnBQ+6klT/aDo1shbwEosr\n" +
  "ss5hUzeyGuJ/8C79z1r/VAUCgYARyWPn7gE9C3Yn6ipJRzINjeOJCBOFy3QkYzGF\n" +
  "3eAB7s8q85Sv08p5sroUZYLOG+Pqr+AXlCQJGrRI9kOT7Cm6v3CDHZ7sfRh4Fsh2\n" +
  "dXnCzucpz6wSJOdWkCI6/FDrhV+PadNHV25guM026w3HfHDYhgZl5ejMhNJnkkpo\n" +
  "SEQhuQKBgQCOcr8gIzQDqTZiGVuotIc2IrPSMAApWIVZD86MLQ5wTPovMPRUd5Oz\n" +
  "WAHsIMrR2pfHviioOgYu8y04WmPHFqGqhkbRIxddalefJdjMR0Ud/uLMij+nh3pA\n" +
  "V/ApuRzW0YDdL/otly27nvTbGHDhXPA+FPMz3q6W1CtTypFnb+Kt8A==\n" +
  "-----END RSA PRIVATE KEY-----"

///|
let rsa_pkcs8 : String = "-----BEGIN PRIVATE KEY-----\n" +
  "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCfF3uvwID81ORh\n" +
  "4SxRD85M7KdmbufqRYpV52zXSlS7LWiK6C8PF90vhaT2m3iCZ4GocpyLugPXOR4g\n" +
  "JsvbUt4cOj34ltoDP5aNybYLGRm3KgzK68W07HaHyZknN97VSN/mJY2qvnXdNvfr\n" +
  "WBOT1rnkR+SP8upvGwgP3+6ImqqyIwO0sujB2EYkROZce+7NPPknisPGTghDDUwl\n" +
  "fvmrVS1OhpYQAHUOW32j3Q4aH8DnS3SuN5N9eIWCeszhKzaTTRToGd+uJwNMkfTL\n" +
  "74KG0AptzmETIjpRjiZk7T/xOoCYEcPqav+Pw7EWKR+YY+9490ekWaT8zCJkax2D\n" +
  "IMWOoEaFAgMBAAECggEAB7OG0MS0Wcjif1x7nTbzKSUhm2NOBbi1ECCCU8+s11zE\n" +
  "3UiNEqF4mxbQnAF9rW5eR+24Z0kra20/6JWIM8dIqjwliNWgmxymaJm1nsbpyESY\n" +
  "VvBf4zi5KiyXpd7eAhwjfowd1gCfSwSgrrtWQ0dXO1ZBmbhMIfHAi6gu71zxW2sj\n" +
  "6wHSr1pMmb7DL+sUjTcrntAmUGLJCesm87vV5TV5P9gKaaHMhF6NQMr1GohOZxzn\n" +
  "jcIUjeB2/lezbfflxX8GTtWrpS1zzLS0JigANSskUhuIwy/iKIddYUEJqNEDtS9S\n" +
  "cj8qKdWL/xipDBldKUlH3XLCS9S20GgTsvrWMEnAsQKBgQDX4ssaHCaKLbjy2mHf\n" +
  "6EsBh/4izcBlxdRDb+fSbFf+7xJf7Wh3BZwBFzWMAqxVZima6oxWGnt0JK8ObIag\n" +
  "/wJ4vctNadGGZZIDrhVb+s0o0FeMvy9mrS0JtOiVp8kQ2d4RtVvZNqyTPYCITZR2\n" +
  "5V++/IhlORxfYnvNtklHssXpPQKBgQC8px5XKpkBZW44m4n7gQddQgtOqSST8qge\n" +
  "dyadqP2MMZi+seNjaXQb5CY+3/DnS3I/i8cicELWecfjme/uwQ1remWcZ/4ZRgQb\n" +
  "+eQgj9s4qcgZJD83L0A8ofGg5dp1AybvnAPcJoTVQEGdUsQSfLhS0IRov9pQ219D\n" +
  "7wM2wf7W6QKBgQCa5hhSaKZieMH+RiD51iOTOq9m63hDzbkqle2g9qoAuirV93MA\n" +
  "C19PDQcXqYdbUw1BIU+GLEQuJnAQil/ivnZYid2IcweqRdCJoWuj7oUr5qkazMbH\n" +
  "BjSNhWdokdXbqGcFD7qSVP9oOjWyFvASiyuyzmFTN7Ia4n/wLv3PWv9UBQKBgBHJ\n" +
  "Y+fuAT0LdifqKklHMg2N44kIE4XLdCRjMYXd4AHuzyrzlK/TynmyuhRlgs4b4+qv\n" +
  "4BeUJAkatEj2Q5PsKbq/cIMdnux9GHgWyHZ1ecLO5ynPrBIk51aQIjr8UOuFX49p\n" +
  "00dXbmC4zTbrDcd8cNiGBmXl6MyE0meSSmhIRCG5AoGBAI5yvyAjNAOpNmIZW6i0\n" +
  "hzYis9IwAClYhVkPzowtDnBM+i8w9FR3k7NYAewgytHal8e+KKg6Bi7zLThaY8cW\n" +
  "oaqGRtEjF11qV58l2MxHRR3+4syKP6eHekBX8Cm5HNbRgN0v+i2XLbue9NsYcOFc\n" +
  "8D4U8zPerpbUK1PKkWdv4q3w\n" +
  "-----END PRIVATE KEY-----"

///|
let rsa_small_public : String = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDBkOQgt71jg/x5pgEQUoxJPj6WFirnZ9GpeX5j9kFa4VNZ3AyxxSJVoueF0e4WT+Ga/tVCRs6QJusaeAK11nZ2bOVfLW41kxkH/zKkwGI3aOdTeabZwZKNEG9WBOH6jgYnK1WeKSKm5TXwex/bhyGvFoUqM7uFVH1uqg5Y5oQSaw== moonseal test small"

///|
/// Randomness that is the same every time.
fn pool(bytes : Int32, seed : Int32) -> @moonseed.Replay {
  @moonseed.Replay::new(
    Bytes::from_array(
      Array::makei(bytes, fn(i) { ((i * 53 + seed * 7) % 256).to_byte() }),
    ),
  )
}

///|
test "a public key reads back as the line it came from" {
  let ed = @ssh.Recipient::of(ed25519_public) catch {
    error => fail("cannot read the Ed25519 key: \{error}")
  }
  assert_eq(ed.kind(), "ssh-ed25519")
  assert_eq(ed.code(), ed25519_public)
  let rsa = @ssh.Recipient::of(rsa_public) catch {
    error => fail("cannot read the RSA key: \{error}")
  }
  assert_eq(rsa.kind(), "ssh-rsa")
  assert_eq(rsa.code(), rsa_public)
}

///|
test "an authorized_keys line may carry options and a comment" {
  let line = "no-pty,command=\"/bin/true\" " +
    ed25519_public +
    " someone@example"
  let recipient = @ssh.Recipient::of(line) catch {
    error => fail("cannot read a line with options: \{error}")
  }
  assert_eq(recipient.code(), ed25519_public)
}

///|
test "a file sealed to an Ed25519 key opens for its holder" {
  let identity = @ssh.Identity::of(ed25519_private) catch {
    error => fail("cannot read the key: \{error}")
  }
  let recipients : Array[&@spec.Recipient] = [identity.public()]
  let file = @moonseal.seal(recipients, b"hello over ssh", random=pool(256, 1)) catch {
    error => fail("cannot seal: \{error}")
  }
  let readers : Array[&@spec.Identity] = [identity]
  assert_eq(@moonseal.open(readers, file), b"hello over ssh")
}

///|
test "a file sealed to an RSA key opens for its holder" {
  let identity = @ssh.Identity::of(rsa_private) catch {
    error => fail("cannot read the key: \{error}")
  }
  let recipients : Array[&@spec.Recipient] = [identity.public()]
  let file = @moonseal.seal(recipients, b"hello over rsa", random=pool(1024, 2)) catch {
    error => fail("cannot seal: \{error}")
  }
  let readers : Array[&@spec.Identity] = [identity]
  assert_eq(@moonseal.open(readers, file), b"hello over rsa")
}

///|
test "the same RSA key opens a file in any of the three formats it comes in" {
  let opener = @ssh.Identity::of(rsa_private) catch {
    error => fail("cannot read the first key: \{error}")
  }
  let recipients : Array[&@spec.Recipient] = [opener.public()]
  let file = @moonseal.seal(
    recipients,
    b"one key, three files",
    random=pool(1024, 3),
  ) catch {
    error => fail("cannot seal: \{error}")
  }
  for text in [rsa_private, rsa_pkcs1, rsa_pkcs8] {
    let identity = @ssh.Identity::of(text) catch {
      error => fail("cannot read a key file: \{error}")
    }
    assert_eq(identity.public().code(), rsa_public)
    let readers : Array[&@spec.Identity] = [identity]
    assert_eq(@moonseal.open(readers, file), b"one key, three files")
  }
}

///|
test "one file for an Ed25519 key, an RSA key and an X25519 key" {
  let ed = @ssh.Identity::of(ed25519_private) catch {
    error => fail("A \{error}")
  }
  let rsa = @ssh.Identity::of(rsa_private) catch { error => fail("B \{error}") }
  let alice = @x25519.Identity::new(Bytes::make(32, 0xA1)) catch {
    error => fail("C \{error}")
  }
  let recipients : Array[&@spec.Recipient] = [
    ed.public(),
    rsa.public(),
    alice.public(),
  ]
  let file = @moonseal.seal(
    recipients,
    b"for the three of you",
    random=pool(1024, 4),
  ) catch {
    error => fail("D \{error}")
  }
  let everyone : Array[&@spec.Identity] = [ed, rsa, alice]
  for identity in everyone {
    let readers : Array[&@spec.Identity] = [identity]
    assert_eq(@moonseal.open(readers, file), b"for the three of you")
  }
}

///|
test "a file addressed to somebody else does not open" {
  let mine = @ssh.Identity::of(ed25519_private) catch {
    error => fail("cannot read the Ed25519 key: \{error}")
  }
  let theirs = @ssh.Identity::of(rsa_private) catch {
    error => fail("cannot read the RSA key: \{error}")
  }
  let recipients : Array[&@spec.Recipient] = [theirs.public()]
  let file = @moonseal.seal(recipients, b"not for me", random=pool(1024, 5)) catch {
    error => fail("cannot seal: \{error}")
  }
  let readers : Array[&@spec.Identity] = [mine]
  let refused = try {
    ignore(@moonseal.open(readers, file))
    false
  } catch {
    @spec.Refused::NoMatch => true
    _ => false
  }
  assert_true(refused)
}

///|
test "a stanza with another key's tag is not mine, not an error" {
  let identity = @ssh.Identity::of(ed25519_private) catch {
    error => fail("cannot read the Ed25519 key: \{error}")
  }
  let stanza = @spec.Stanza::new(
    kind="ssh-ed25519",
    args=["AAAA", "AAAA"],
    body=Bytes::make(32, 0),
  )
  assert_true(identity.unwrap(stanza~) is None)
}

///|
test "a malformed stanza of a known type is a refusal" {
  let ed = @ssh.Identity::of(ed25519_private) catch {
    error => fail("cannot read the RSA key: \{error}")
  }
  let one_argument = @spec.Stanza::new(
    kind="ssh-ed25519",
    args=[ed.public().fingerprint()],
    body=Bytes::make(32, 0),
  )
  let refused = try {
    ignore(ed.unwrap(stanza=one_argument))
    false
  } catch {
    @spec.Refused::Stanza(..) => true
    _ => false
  }
  assert_true(refused)
  let rsa = @ssh.Identity::of(rsa_private) catch {
    error => fail("cannot seal: \{error}")
  }
  let two_arguments = @spec.Stanza::new(
    kind="ssh-rsa",
    args=[rsa.public().fingerprint(), "AAAA"],
    body=Bytes::make(256, 0),
  )
  let refused = try {
    ignore(rsa.unwrap(stanza=two_arguments))
    false
  } catch {
    @spec.Refused::Stanza(..) => true
    _ => false
  }
  assert_true(refused)
}

///|
test "an RSA key below 2048 bits is refused" {
  let refused = try {
    ignore(@ssh.Recipient::of(rsa_small_public))
    false
  } catch {
    @spec.Refused::Stanza(..) => true
    _ => false
  }
  assert_true(refused)
}

///|
test "a key type this library does not implement is refused" {
  let refused = try {
    ignore(@ssh.Recipient::of("ssh-dss AAAAB3NzaC1kc3MAAACBAP"))
    false
  } catch {
    @spec.Refused::Stanza(..) => true
    _ => false
  }
  assert_true(refused)
  let refused = try {
    ignore(@ssh.Recipient::of("not a key at all"))
    false
  } catch {
    @spec.Refused::Stanza(..) => true
    _ => false
  }
  assert_true(refused)
}
