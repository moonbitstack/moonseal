// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Two files the reference implementation sealed to the keys above, armored.
/// They are here because a stanza this library writes and a stanza it reads can
/// agree with each other and both be wrong: only bytes from another
/// implementation pin the tag, the OAEP label and the derivation.
let age_ed25519_file : String = "-----BEGIN AGE ENCRYPTED FILE-----\n" +
  "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNzaC1lZDI1NTE5IGRyWk1kUSBGSG55\n" +
  "QnRUTW8zRDdOWUVtQzluckUvcnRIbU82ZGg0VlZRZDcrNEJjbERNCnZsNmRqZzhX\n" +
  "VFJmVmxqaHBzemxwU0RWK01jRk9QVURuMDYvUm45R3ozeU0KLS0tIFlrU0RWZFNL\n" +
  "SkJBZmt5WVdsMEFNVWVuaU1PMkFKN29wMEcySmZmUlVtMG8KLu6oZ2swlMryuP88\n" +
  "FjbAwNJnhvBiSAFoEOqSvgiBcXRe0WmLEDIGVePVOZJh3V3jnvGLqlzSKcLAq3bL\n" +
  "2fkTUe03z6GxZvo=\n" +
  "-----END AGE ENCRYPTED FILE-----"

///|
let age_rsa_file : String = "-----BEGIN AGE ENCRYPTED FILE-----\n" +
  "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNzaC1yc2EgY2IvcU1BCmtPcmVEVFVo\n" +
  "ZlVMMm9ibHRZZTZpR1Z0U3p5bUJlbDNGdzY0Rmx0RTYyNEZESDNmMmUvemRUM3Z3\n" +
  "dFd4c1VLYmYKTVBkZjBmSVVNK2thLzNOZkRJUFJDR2hwTlpXRDRMYnFXMm1uNjFh\n" +
  "NGI4WDJCcS9aZzc4cC9CaVhJOUsxZUYrMgpTOXBOYURMUVpGVFZsT2ViSkMyajRw\n" +
  "NktUWEFmTzJzS3paeWs1dWpuTGJhR2lwVFFKKzlpbklvVWlHQ1BmeHNPCmlHMDdl\n" +
  "UWxrNjdkZEJkNTFDUHlPTElHYVk0aXhoK2VjOWM4U2taUDU4ZVBwbzZRdGFYSmVi\n" +
  "VzBkbmMvWGNRajUKVkdUMXo1T3ZoMlJ3RHU2ZmJseHY2cDYyK20wZi8rMWkya3RC\n" +
  "bmd4WGIwV1dJQnl5eVhPdkp3UjM1S29SR0wwRApXdHRvS2JjditvZnAxMk1EUVdL\n" +
  "T2NBCi0tLSBlYlVvQ3ZaVVdtVitpMklxMXc4bEtPZ0M4VUloM3lkRDJUZ2lEZG1y\n" +
  "dndVCjCEts1IG/YYxsJDir6Hpqlepou/6yzgdM5XFqq3wEoJIs/M0fBGBZvUd13Z\n" +
  "bdmTt2aLlgv1b0+tN4/pXgWc+AQWEepx/6hL\n" +
  "-----END AGE ENCRYPTED FILE-----"

///|
let age_plain : Bytes = b"sealed by the reference implementation\n"

///|
test "the four-byte tag is the start of the key's hash" {
  assert_eq(@ssh.Recipient::of(ed25519_public).fingerprint(), "drZMdQ")
  assert_eq(@ssh.Recipient::of(rsa_public).fingerprint(), "cb/qMA")
}

///|
test "a file the reference implementation sealed opens here" {
  let ed = @ssh.Identity::of(ed25519_private) catch {
    error => fail("cannot read the Ed25519 key: \{error}")
  }
  let readers : Array[&@spec.Identity] = [ed]
  assert_eq(@moonseal.open_armored(readers, age_ed25519_file), age_plain)
  let rsa = @ssh.Identity::of(rsa_private) catch {
    error => fail("cannot read the RSA key: \{error}")
  }
  let readers : Array[&@spec.Identity] = [rsa]
  assert_eq(@moonseal.open_armored(readers, age_rsa_file), age_plain)
}
