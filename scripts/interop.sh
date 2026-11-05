#!/usr/bin/env bash
#
# Exchange files with other age implementations, in both directions, once per
# recipient type:
#
#     scripts/interop.sh <path-to-the-interop-example>
#
# `age` (FiloSottile/age, 1.3 or later for the post-quantum type) and `rage`
# have to be on PATH. A passphrase is typed through a pseudo-terminal because
# both tools read one from the terminal and never from a pipe; `script` from
# util-linux is what provides one here, which is why this runs on Linux only.
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

echo "keys"
age-keygen -o x25519.key 2> /dev/null
x25519=$(sed -n 's/^# public key: //p' x25519.key)
age-keygen -pq -o pq.key 2> /dev/null
pq=$(sed -n 's/^# public key: //p' pq.key)
ssh-keygen -q -t ed25519 -N '' -C 'moonseal interop' -f ed25519.key
ssh-keygen -q -t rsa -b 2048 -N '' -C 'moonseal interop' -f rsa.key
ed25519=$(cut -d ' ' -f 1,2 ed25519.key.pub)
rsa=$(cut -d ' ' -f 1,2 rsa.key.pub)

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
