#!/usr/bin/env python3
"""Turn a checkout of the C2SP age test vectors into a MoonBit source file.

    scripts/vectors.py ~/src/CCTV/age/testdata

The vectors are published as one file per case: header lines of `key: value`,
a blank line, then the file itself (zlib-compressed when the case is large).
They are the authority on what this library has to accept and what it has to
refuse, so they are built into the test binary rather than read from disk: a
test that needs a working directory is a test that fails on the wasm backends.

Run this again when the vectors change, and commit the output with them.
"""

import base64
import os
import sys
import zlib

EXPECT = {
    "success": "Success",
    "header failure": "HeaderFailure",
    "payload failure": "PayloadFailure",
    "HMAC failure": "MacFailure",
    "no match": "NoMatch",
    "armor failure": "ArmorFailure",
}

# Recipient types this library does not implement. A vector that names one of
# these keys cannot be judged here either way: the file may open through a
# stanza type that is not in this library.
UNSUPPORTED = "AGE-SECRET-KEY-PQ-"


# A vector whose file is larger than this is left out of the build. The three
# that are, are the 258-chunk streaming cases: sixteen mebibytes of mostly zeros
# each, which the test of chunk numbering below already covers a chunk at a
# time.
LIMIT = 1 << 20


def parse(path):
    with open(path, "rb") as handle:
        raw = handle.read()
    lines = raw.split(b"\n")
    meta = {}
    body = b""
    for i, line in enumerate(lines):
        text = line.rstrip(b"\r").decode("utf-8", "replace")
        if text == "":
            body = b"\n".join(lines[i + 1 :])
            break
        key, _, value = text.partition(": ")
        meta.setdefault(key, []).append(value)
    if meta.get("compressed") == ["zlib"]:
        body = zlib.decompress(body)
    return meta, body


def moon_string(text):
    out = ['"']
    for byte in text.encode("utf-8"):
        char = chr(byte)
        if char == '"':
            out.append('\\"')
        elif char == "\\":
            out.append("\\\\")
        elif 32 <= byte < 127:
            out.append(char)
        else:
            out.append("\\u{%x}" % byte)
    out.append('"')
    return "".join(out)


def wrapped(text, width=48):
    """A string literal long enough to read, cut into pieces the formatter keeps
    on one line each."""
    if len(text) <= width:
        return moon_string(text)
    pieces = [text[i : i + width] for i in range(0, len(text), width)]
    return " +\n      ".join(moon_string(piece) for piece in pieces)


def main(argv):
    if len(argv) != 2:
        sys.exit(__doc__)
    source = argv[1]
    names = sorted(os.listdir(source))
    lines = [
        "// Copyright 2026 Leo Cheng",
        "// SPDX-License-Identifier: Apache-2.0",
        "",
        "///|",
        "/// What a case in the C2SP age test vectors is supposed to do.",
        "pub(all) enum Expect {",
        "  Success",
        "  HeaderFailure",
        "  PayloadFailure",
        "  MacFailure",
        "  NoMatch",
        "  ArmorFailure",
        "  Skipped",
        "} derive(Eq, Debug)",
        "",
        "///|",
        "pub extend Expect with Eq::{equal, not_equal}",
        "",
        "///|",
        "pub extend Expect with Debug::{to_repr}",
        "",
        "///|",
        "pub extend Expect with Show::{to_string, output}",
        "",
        "///|",
        "pub impl Show for Expect with fn output(self, logger) {",
        "  logger.write_string(match self {",
        "    Success => \"success\"",
        "    HeaderFailure => \"header failure\"",
        "    PayloadFailure => \"payload failure\"",
        "    MacFailure => \"HMAC failure\"",
        "    NoMatch => \"no match\"",
        "    ArmorFailure => \"armor failure\"",
        "    Skipped => \"skipped\"",
        "  })",
        "}",
        "",
        "///|",
        "pub(all) struct Vector {",
        "  name : String",
        "  expect : Expect",
        "  armored : Bool",
        "  identities : Array[String]",
        "  passphrases : Array[String]",
        "  digest : String",
        "  data : String",
        "}",
        "",
        "///|",
        "/// The vectors, one entry per file in `age/testdata` of the C2SP",
        "/// certificate transparency test suite.",
        "pub let vectors : Array[Vector] = [",
    ]
    skipped = []
    for name in names:
        path = os.path.join(source, name)
        if not os.path.isfile(path):
            continue
        meta, body = parse(path)
        expect = EXPECT[meta["expect"][0]]
        identities = meta.get("identity", [])
        reason = None
        if any(identity.startswith(UNSUPPORTED) for identity in identities):
            reason = "needs a recipient type this library does not have"
        elif len(body) > LIMIT:
            reason = "%d bytes, over the %d this build embeds" % (len(body), LIMIT)
        if reason is not None:
            expect = "Skipped"
            skipped.append((name, reason))
            body = b""
        lines.append("  {")
        lines.append("    name: %s," % moon_string(name))
        lines.append("    expect: %s," % expect)
        lines.append(
            "    armored: %s," % ("true" if meta.get("armored") == ["yes"] else "false")
        )
        lines.append(
            "    identities: [%s],"
            % ", ".join(moon_string(item) for item in identities)
        )
        lines.append(
            "    passphrases: [%s],"
            % ", ".join(moon_string(item) for item in meta.get("passphrase", []))
        )
        lines.append(
            "    digest: %s," % moon_string(meta.get("payload", [""])[0])
        )
        lines.append("    data: %s," % wrapped(base64.b64encode(body).decode("ascii")))
        lines.append("  },")
    lines.append("]")
    lines.append("")
    out = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "src",
        "tests",
        "cctv",
        "vectors.mbt",
    )
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))
    print("wrote %s: %d vectors, %d skipped" % (out, len(names), len(skipped)))
    for name, reason in skipped:
        print("  skipped %s (%s)" % (name, reason))


if __name__ == "__main__":
    main(sys.argv)
