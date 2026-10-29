"""Fill the API panel of docs/index.html from the package interfaces.

Every public type, value and function comes from the `pkg.generated.mbti` that
`moon info` writes, with the `///` comment above its definition; the package
line under each heading is the first paragraph of its `moon.pkg` comment.

Usage: moon info --target all && python scripts/gen_api.py
"""

import html
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
PAGE = ROOT / "docs" / "index.html"

# The container first, then its contract, then the parts it is made of.
PACKAGES = ["", "spec", "header", "stream", "armor", "x25519", "scrypt"]

# Methods `derive` adds. They are in the derive clause already.
DERIVED = {"equal", "not_equal", "to_repr", "output", "to_string", "hash"}

DECL = re.compile(
    r"pub(?:\([a-z]+\))?\s+(?:"
    r"fn(?:\[[^\]]*\])?\s+(?P<fn>[A-Za-z0-9_:]+)"
    r"|let\s+(?P<value>\w+)"
    r"|suberror\s+(?P<error>\w+)"
    r"|struct\s+(?P<struct>\w+)"
    r"|enum\s+(?P<enum>\w+)"
    r"|trait\s+(?P<trait>\w+)"
    r"|impl(?:\[[^\]]*\])?\s+(?P<impl>.+)"
    r")"
)


def named(m: re.Match) -> tuple:
    kind = m.lastgroup or ""
    return kind, m.group(kind).strip()


def declarations(path: str) -> list:
    lines = (SRC / path / "pkg.generated.mbti").read_text(encoding="utf-8").splitlines()
    out, i = [], 0
    while i < len(lines):
        if not lines[i].startswith("pub"):
            i += 1
            continue
        block, depth = [], 0
        while i < len(lines):
            block.append(lines[i])
            depth += lines[i].count("{") - lines[i].count("}")
            i += 1
            if depth <= 0:
                break
        text = "\n".join(block)
        m = DECL.match(text)
        if m:
            kind, name = named(m)
            out.append({"kind": kind, "name": name, "sig": text})
    return out


def doc_comments(path: str) -> dict:
    docs = {}
    for file in sorted((SRC / path).glob("*.mbt")):
        if file.name.endswith("_test.mbt"):
            continue
        lines = file.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            if line != "///|":
                continue
            j, body = i + 1, []
            while j < len(lines) and lines[j].startswith("///"):
                body.append(lines[j][3:].strip())
                j += 1
            if not body or j >= len(lines):
                continue
            m = DECL.match(lines[j])
            if not m or m.lastgroup == "impl":
                continue
            paragraphs = [" ".join(p.split("\n")) for p in "\n".join(body).split("\n\n") if p.strip()]
            docs.setdefault(named(m)[1], paragraphs)
    return docs


def summary(path: str) -> str:
    first = []
    for line in (SRC / path / "moon.pkg").read_text(encoding="utf-8").splitlines():
        if not line.startswith("//"):
            break
        text = line[2:].strip()
        if not text:
            if first:
                break
            continue
        first.append(text)
    return " ".join(first)


def prose(text: str) -> str:
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", html.escape(text, quote=False))


def sig(text: str) -> str:
    # The return type is what a reader scans for, so it gets the accent.
    body = html.escape(text, quote=False)
    return re.sub(r"-&gt; ([^\n]+)$", r'-&gt; <span class="r">\1</span>', body)


def entry(decl: dict, docs: dict) -> str:
    out = f'        <div class="fn"><div class="sig">{sig(decl["sig"])}</div>'
    for p in docs.get(decl["name"], []):
        out += f'<div class="d">{prose(p)}</div>'
    return out + "</div>\n"


def package(path: str) -> tuple:
    decls = declarations(path)
    docs = doc_comments(path)
    types = [d for d in decls if d["kind"] in {"trait", "struct", "enum", "error"}]
    owned = {t["name"] for t in types}
    methods, free = {}, []
    for d in decls:
        if d["kind"] != "fn":
            continue
        owner, _, short = d["name"].rpartition("::")
        if owner in owned:
            if short not in DERIVED or d["name"] in docs:
                methods.setdefault(owner, []).append(d)
        else:
            free.append(d)
    values = [d for d in decls if d["kind"] == "value"]
    rank = {"trait": 0, "struct": 1, "enum": 1, "error": 2}
    body = []
    for t in sorted(types, key=lambda t: (rank[t["kind"]], t["name"])):
        body.append(entry(t, docs))
        body += [entry(m, docs) for m in methods.get(t["name"], [])]
    body += [entry(v, docs) for v in values]
    body += [entry(f, docs) for f in free]
    name = path or "moonseal"
    slug = f"pkg-{name}"
    section = (
        f'      <div class="pkg" id="{slug}">\n'
        f"        <h3>{name}</h3>\n"
        f'        <p class="desc">{prose(summary(path))}</p>\n'
        + "".join(body)
        + "      </div>\n"
    )
    nav = f'      <a href="#{slug}">{name}</a>\n'
    return section, nav


def fill(page: str, region: str, body: str) -> str:
    start, end = f"<!-- generated:{region} -->", f"<!-- /generated:{region} -->"
    a, b = page.index(start) + len(start), page.index(end)
    return page[:a] + "\n" + body + page[b:]


def main():
    sections, navs = zip(*(package(p) for p in PACKAGES))
    page = PAGE.read_text(encoding="utf-8")
    page = fill(page, "api", "\n".join(sections))
    page = fill(page, "nav", "".join(navs))
    PAGE.write_text(page, encoding="utf-8", newline="\n")
    print(f"{len(PACKAGES)} packages written")


if __name__ == "__main__":
    main()
