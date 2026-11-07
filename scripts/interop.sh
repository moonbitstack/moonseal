#!/usr/bin/env bash
#
# Exchange files with other age implementations, in both directions, once per
# recipient type:
#
#     scripts/interop.sh <path-to-the-interop-example>
#
# `age` (FiloSottile/age, 1.3 or later for the post-quantum type, 1.3.2 or later
# for the tagged ones) and `rage` have to be on PATH. The tagged recipients also
# want `age-plugin-tagtest`, the plugin age's own tests use to open files
# addressed to them: without it, one half of that exchange is skipped.
#
# A passphrase is typed through a pseudo-terminal because both tools read one
# from the terminal and never from a pipe; `script` from util-linux is what
# provides one here, which is why this runs on Linux only.
#
# Every check writes a file with one implementation and reads it with the other,
# then compares it with the plaintext: "the command exited zero" is not what a
# file format promises.

set -euo pipefail

bin=$(cd "$(dirname "${1:?usage: scripts/interop.sh <interop-binary>}")" && pwd)/$(basename "$1")

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

pass='correct horse battery staple'
printf 'the quick brown fox jumps over the lazy dog\n' > plain.txt

# A passphrase, typed into a pseudo-terminal. Both tools ask the terminal for
# one — age directly, rage through pinentry — and both draw a prompt before they
# listen. The keys go one at a time and slowly, because a pinentry-curses form
# loses a burst typed into it before it has drawn its fields.
type_passphrase() {
  sleep 1
  for _ in $(seq "$1"); do
    at=0
    while [ "$at" -lt "${#pass}" ]; do
      printf '%s' "${pass:$at:1}"
      sleep 0.05
      at=$((at + 1))
    done
    printf '\r'
    sleep 1
  done
  sleep 1
}

passed=0
failed=0

report() {
  printf '  %-52s %s\n' "$1" "$2"
}

pass() {
  passed=$((passed + 1))
  report "$1" "ok"
}

fail() {
  failed=$((failed + 1))
  report "$1" "FAILED"
}

# A file this library wrote, opened by $1.
theirs() {
  local tool=$1 identity=$2 label=$3
  if "$tool" -d -i "$identity" -o opened.txt ours.age > /dev/null 2>&1 &&
    cmp -s plain.txt opened.txt; then
    pass "$label: moonseal seals, $tool opens"
  else
    fail "$label: moonseal seals, $tool opens"
  fi
}

# A file $1 wrote, opened by this library.
ours() {
  local tool=$1 recipient=$2 identity=$3 label=$4
  if "$tool" -e -r "$recipient" -o theirs.age plain.txt > /dev/null 2>&1 &&
    "$bin" open theirs.age opened.txt "$identity" > /dev/null 2>&1 &&
    cmp -s plain.txt opened.txt; then
    pass "$label: $tool seals, moonseal opens"
  else
    fail "$label: $tool seals, moonseal opens"
  fi
}

# A file this library wrote, opened by age through its tag-test plugin — whose
# identity is a constant, so the recipient has to be that identity's — and a
# file age wrote, opened by this library.
tagged() {
  local label=$1 recipient=$2 identity_file=$3
  printf '%s\n' "$recipient" > recipients.txt
  if ! "$bin" seal plain.txt ours.age recipients.txt > /dev/null; then
    fail "$label: moonseal seals"
  elif ! command -v age-plugin-tagtest > /dev/null; then
    report "$label: moonseal seals, age opens" "skipped, no age-plugin-tagtest"
  elif age -d -j tagtest -o opened.txt ours.age > /dev/null 2>&1 &&
    cmp -s plain.txt opened.txt; then
    pass "$label: moonseal seals, age opens"
  else
    fail "$label: moonseal seals, age opens"
  fi
  ours age "$recipient" "$identity_file" "$label"
}

echo "keys"
age-keygen -o x25519.key 2> /dev/null
x25519=$(sed -n 's/^# public key: //p' x25519.key)
age-keygen -pq -o pq.key 2> /dev/null
pq=$(sed -n 's/^# public key: //p' pq.key)
ssh-keygen -q -t ed25519 -N '' -C 'moonseal interop' -f ed25519.key
ssh-keygen -q -t rsa -b 2048 -N '' -C 'moonseal interop' -f rsa.key
ed25519=$(cut -d ' ' -f 1,2 ed25519.key.pub)
rsa=$(cut -d ' ' -f 1,2 rsa.key.pub)

# The identity age's tag-test plugin holds, and the two recipients that are its
# public halves. They are constants in that plugin, derived from the string
# `age-plugin-tagtest`, which is why the identity files below name that string
# and not a key: the format defines no written form for these identities.
tag='age1tag1qwe0kafsjrar4txm6heqnhpfuggzr0gvznz7fvygxrlq90u5mq2pysxtw6h'
tagpq='age1tagpq14h4z7cks9sxftfc8tq4xektt4854ur9rv76tvujdvtzk2fmyywkvh9z2emz3x4epvhz7qdt2v7uksyyq2cdzf3k04ny0g5sc3u4heqh3r9v4cnwhfjw0a2azpgmnk9xk02wvywt5szcq6q3jvwsjxvkn3tsk52vqjczdcvc398ym4j6cvqas4w99gkgt7ur3fmt4g873phr23tgxw3f7wgsz9zxz7m8cp27vpq3h5vc8nssjemtr2etmtmqkg4fzn2u9x9zvtysuya5yrytgx482ftx9864h8a6pprarxd3d0qe8nw2at5ekg3tsahtef7kawasxjamyckw2ans6v933vuypcfrra32f89r2v72mka9hhc55s49xe2khfsq7w9r2zynuzfx4fg6v7jjncsc87rw2yy8qp8hr27edus6zw5xd6m3hax2nxhl2dys9792z3wp5c034sfkrxe86guj7pfdh7sytzrufl9euhuhyf9w6c7z2nwf7v5v8f2s4gplgvfx4jj4le22k2qn242qkqkcwx7llfyrct7jm2wcv0ytypeh6h93ezgtd7q6zr428qze3dec5jxlc5xxjetyephp42fljft3s02p0570kjwyfeyjcnks2vglkvyus5g9l4z6m0gf8wu22ygfm40028txwjlxvvgnn7c36z783c6tmc9k5nef8nucj6u3ustff5vhtnzhnscsvsz79wzrkv3sujtntx4wezucy6lp49flmnyydn3khk2xsesw0ekn4u44nzqw2g2rjyrrl7crshlzttgpe0jvqycjzp9kmtz23t3yu0w9j4n344nnrf88k2jqqfpjxte38pcn0epr879pqsuvajxrkmsas89pvfrzwcewneujn08guj5pvvrtn5hzzg2y6u4wwjqqxx4x8w65yc4dchf750dft8kgcttt2f6j0j5v8s7tkaua78tte7artdfar544vl0rau79h95mc4ghp887z82s6rq93txpkvan86n963kagqkldngnkjcn28zdrh38vdxj002zqs9mx7zjvg3ynzdfhfakkynt9fyqpaxpsdrsqrycuhw5ykwgjz6wldef7xtu6p689234hstxe7v8e5422f2dy8ystn57z3fvy9yfrm4t3lye6ejk5n6x8zqexmql7lx965xcxuuy38xzyt8j9qprnwgfqgx54l4tnjdpzdde6xgmwtnpkfwvyr7rkgnavvjn6a3e56wtvjx3evmhjjxvukpq5zqrj0s4sntkz3yeszs5dty8q0q6m7dgp6mjpvaer0c4343g72eycfqzkjupeaemh0n8e935hqs8fh3jgk7fzyxctzuqlx6d2q9jaf8r9wu4sjxj5w6ppw7m9c3hxrzpcv2uek3kxnndgf2hd99q9v2ux8pjkv29ntslvnvhy09dvcy9578rt89gf4cj4cu79zjxtlj3dpct6rjme02zj3qspsade96njkkufu9zuq2lk3qwvddpxjkqm2hnpqwck54zug7ctvkgvk325lwkg4q5rf73zkgys5e9y8jqc96ntdyl4r78lgtw4k5uljk5ttf46s3gc0rq0jwmddnxt875twwq92505zh3zkse5ag2dhjjxyfzkn7xv3j0kv9r3jzpvgep8fq6z8mar509u4fvnhvthp2ah0r45lsyq0mm6fwkcs30v8k9wzvgt6uvcty6qsjvarjs3htym69zu43m4jd3k4tllrr8c05v6p6spuhup4hkk2p9fp9lxafe3pntcn4nk83gzhjjpcjwyg7jcyz5uancu0fakgz27up7ymzp2xv3sqyqewkkqynskw9qkvysrncxj0cy7dt6q8dsseuwmc2urfmcvkykf82wfa54t85hqx8gywhmhzunm2x0d66a4pwl0xl78fhkces5dpq8pfnp35m5a3u8vdam64zx5s5x9cmnrx3zr066f4f8hlecqnq2fd5quw79ljg3q5nvs6ggmm4gkc'
printf 'tag-seed:age-plugin-tagtest\n' > tag.txt
printf 'tagpq-seed:age-plugin-tagtest\n' > tagpq.txt

for tool in age rage; do
  command -v "$tool" > /dev/null || {
    echo "  $tool is not installed"
    failed=$((failed + 1))
    continue
  }
  echo "$("$tool" --version | head -1)"

  # ---------------------------------------------------------------- X25519
  printf '%s\n' "$x25519" > recipients.txt
  if "$bin" seal plain.txt ours.age recipients.txt > /dev/null; then
    theirs "$tool" x25519.key "x25519"
  else
    fail "x25519: moonseal seals"
  fi
  ours "$tool" "$x25519" x25519.key "x25519"

  # ------------------------------------------------------------ ssh-ed25519
  printf '%s\n' "$ed25519" > recipients.txt
  if "$bin" seal plain.txt ours.age recipients.txt > /dev/null; then
    theirs "$tool" ed25519.key "ssh-ed25519"
  else
    fail "ssh-ed25519: moonseal seals"
  fi
  ours "$tool" "$ed25519" ed25519.key "ssh-ed25519"

  # ---------------------------------------------------------------- ssh-rsa
  printf '%s\n' "$rsa" > recipients.txt
  if "$bin" seal plain.txt ours.age recipients.txt > /dev/null; then
    theirs "$tool" rsa.key "ssh-rsa"
  else
    fail "ssh-rsa: moonseal seals"
  fi
  ours "$tool" "$rsa" rsa.key "ssh-rsa"

  # ------------------------------------------------- post-quantum hybrid
  # A tool that has never heard of the type refuses the recipient; that is a
  # gap in the tool's version, not a disagreement about the format, so the
  # check is skipped and said so rather than counted as a failure.
  if "$tool" -e -r "$pq" -o probe.age plain.txt > /dev/null 2>&1; then
    printf '%s\n' "$pq" > recipients.txt
    if "$bin" seal plain.txt ours.age recipients.txt > /dev/null; then
      theirs "$tool" pq.key "mlkem768x25519"
    else
      fail "mlkem768x25519: moonseal seals"
    fi
    ours "$tool" "$pq" pq.key "mlkem768x25519"
  else
    report "mlkem768x25519: $tool has no post-quantum recipient" "skipped"
  fi

  # ------------------------------------------------------------- tagged
  # A tagged recipient is a hardware key's public half, and a tool's only way to
  # open one is a plugin. `rage` has no such recipients at all, which is a gap in
  # the tool rather than a disagreement about the format.
  if [ "$tool" = age ]; then
    tagged "p256tag" "$tag" tag.txt
    tagged "mlkem768p256tag" "$tagpq" tagpq.txt
  else
    report "tagged recipients: $tool has none" "skipped"
  fi

  # -------------------------------------------------------------- scrypt
  printf 'passphrase:%s\n' "$pass" > recipients.txt
  if "$bin" seal plain.txt ours.age recipients.txt > /dev/null; then
    { type_passphrase 1 |
      timeout 60 script -qec "$tool -d -o opened.txt ours.age" /dev/null > /dev/null 2>&1; } || true
    if cmp -s plain.txt opened.txt; then
      pass "scrypt: moonseal seals, $tool opens"
    else
      fail "scrypt: moonseal seals, $tool opens"
    fi
  else
    fail "scrypt: moonseal seals"
  fi
  if [ "$tool" = age ]; then
    { type_passphrase 2 |
      timeout 60 script -qec "age -p -o theirs.age plain.txt" /dev/null > /dev/null 2>&1; } || true
    printf 'passphrase:%s\n' "$pass" > identity.txt
    if "$bin" open theirs.age opened.txt identity.txt > /dev/null 2>&1 &&
      cmp -s plain.txt opened.txt; then
      pass "scrypt: age seals, moonseal opens"
    else
      fail "scrypt: age seals, moonseal opens"
    fi
  else
    # rage asks for a passphrase in a curses form of its own, which a script
    # cannot type into with any confidence; its single-prompt path above is the
    # half of the exchange that a terminal can answer.
    report "scrypt: $tool seals, moonseal opens" "skipped, no scriptable prompt"
  fi
done

echo
if [ "$failed" -ne 0 ]; then
  echo "interop: $passed passed, $failed failed"
  exit 1
fi
echo "interop: $passed checks passed"
