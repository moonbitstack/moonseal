// The console on the home page. Every command that seals or opens calls
// moonseal built to JavaScript (engine/moonseal.js, written by the docs
// workflow), so the files it prints are age files.

const root = document.documentElement;
const syncTop = () => root.classList.toggle("at-top", window.scrollY <= 0);
window.addEventListener("scroll", syncTop, { passive: true });
syncTop();

// The API panel's package list stays just under the header, whatever height
// the header wraps to.
{
  const bar = document.querySelector("header.bar");
  const nav = document.querySelector(".api-nav-inner");
  if (bar && nav) {
    const set = () => {
      nav.style.top = `${bar.offsetHeight + 22}px`;
      nav.style.maxHeight = `calc(100vh - ${bar.offsetHeight + 38}px)`;
    };
    set();
    window.addEventListener("resize", set, { passive: true });
  }
}

const OUT = document.getElementById("out");
const engine = import(new URL("../engine/moonseal.js", import.meta.url).href);

// The library's default work factor is 2^18, a second or more of native code.
// The page uses less so that it answers at once; `--work` raises it.
const WORK = 12;

let KEY = null;
let LAST = null;

// A row of coloured spans. A row of a file keeps its width and scrolls.
function row(kind, ...parts) {
  const el = document.createElement("div");
  if (kind) el.className = kind;
  for (const [cls, text] of parts) {
    const span = document.createElement("span");
    span.className = cls;
    span.textContent = text;
    el.appendChild(span);
  }
  OUT.appendChild(el);
  OUT.scrollTop = OUT.scrollHeight;
}
const line = (...parts) => row(null, ...parts);
const say = (...parts) => line(["pr", "› "], ...parts);
const err = (message) => line(["er", "error: "], ["cr", message]);

async function call(name, ...args) {
  const m = await engine;
  const result = JSON.parse(m[name](...args));
  if (!result.ok) throw new Error(result.error);
  return result.value;
}

function printFile(text) {
  for (const l of text.trimEnd().split("\n")) {
    row("file", [l.startsWith("-----") ? "cm" : "dm", l]);
  }
}

// One argument per word, a quoted run counting as one.
function tokenize(s) {
  const out = [];
  for (const m of s.matchAll(/"([^"]*)"|(\S+)/g)) out.push(m[1] ?? m[2]);
  return out;
}

function flags(args) {
  const f = { to: [], rest: [] };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--pass") f.pass = args[++i];
    else if (a === "--to") f.to.push(args[++i]);
    else if (a === "--with") f.with = args[++i];
    else if (a === "--work") f.work = Number(args[++i]);
    else if (a === "--me") f.me = true;
    else f.rest.push(a);
  }
  return f;
}

const yieldFrame = () => new Promise((r) => setTimeout(r, 20));

const HELP = [
  ["install", "how to add the library"],
  ["keygen", "make an X25519 identity"],
  ['seal --pass "PW" "MSG"', "seal to a passphrase (--work N for 2^N)"],
  ['seal --to age1… "MSG"', "seal to one or more public keys"],
  ['seal --me "MSG"', "seal to the keygen key"],
  ['open --pass "PW"', "open the last file"],
  ["open --with AGE-SECRET-KEY-1…", "open with a secret key"],
  ["open --me", "open with the keygen key"],
  ["inspect", "read the last file's header"],
  ["recipients | armor | stream | custom", "explain a feature"],
  ["api", "jump to the API reference"],
  ["clear", "empty the screen"],
];

const CMDS = {
  help() {
    line(["dm", "commands — the guide is in the commands."]);
    for (const [c, d] of HELP) line(["cm", `  ${c.padEnd(32)}`], ["dm", d]);
  },
  clear() {
    OUT.replaceChildren();
  },
  install() {
    line(["dm", "moon add "], ["am", "moonbitstack/moonseal"]);
    line(["dm", "moon add "], ["am", "moonbitstack/moonrand"], ["dm", "   # the random source"]);
    line(["dm", "Then import the packages you use: "], ["cm", "moonseal"], ["dm", ", "], ["cm", "x25519"], ["dm", ", "], ["cm", "scrypt"], ["dm", ", "], ["cm", "moonrand/system"], ["dm", "."]);
  },
  about() {
    line(["cr", "Seal a file for several people at once; any one of them opens it. A format, not a vault."]);
  },
  recipients() {
    line(["dm", "One file, many readers. Address it to a list of recipients:"]);
    line(["cr", "seal([alice.public(), bob.public()], plain, random=@system.source)"]);
    line(["dm", "A passphrase stanza must stand alone: mixing it with a public key is refused."]);
    line(["dm", "Any single identity on the list opens the whole file on its own. Try "], ["cm", "seal --to age1… --to age1… \"MSG\""], ["dm", "."]);
  },
  armor() {
    line(["dm", "Somewhere a file has to survive an email. The armor writes the same bytes as:"]);
    line(["cr", "-----BEGIN AGE ENCRYPTED FILE-----"]);
    line(["dm", "…base64, 64 columns…"]);
    line(["cr", "-----END AGE ENCRYPTED FILE-----"]);
    line(["dm", "Every file this console prints is armored. Reading is stricter than writing: stray"]);
    line(["dm", "whitespace and either line ending are allowed; a wrong width or a second spelling is not."]);
  },
  stream() {
    line(["dm", "Files larger than memory are sealed a chunk at a time: 64 KiB, each with its own 16-byte tag."]);
    line(["cr", "seal_stream(sink, recipients, source, random=@system.source)"]);
    line(["dm", "Nothing bigger than one chunk plus a header is ever held. Attach a file, a socket or a pipe"]);
    line(["dm", "by implementing Source::read and Sink::write; this library never learns which it is."]);
  },
  custom() {
    line(["dm", "Recipients are a trait. Add your own type with two methods:"]);
    line(["cr", "impl @spec.Recipient for Mine with fn wrap(self, file_key~, random~) { … }"]);
    line(["cr", "impl @spec.Identity for Mine with fn unwrap(self, stanza~) { … }"]);
    line(["dm", "None means \"not mine, try the next stanza\". A malformed stanza of your type is a refusal."]);
  },
  api() {
    document.getElementById("api").scrollIntoView({ behavior: "smooth" });
    line(["dm", "→ the API reference is below."]);
  },
  async keygen() {
    KEY = await call("keygen");
    line(["ok", "identity generated, kept in this tab only"]);
    line(["dm", "  secret: "], ["am", KEY.secret]);
    line(["dm", "  public: "], ["cm", KEY.public]);
    line(["dm", "try: "], ["cr", 'seal --me "a note to myself"'], ["dm", "  then  "], ["cr", "open --me"]);
  },
  async seal(args) {
    const f = flags(args);
    const message = f.rest.join(" ");
    if (!message) return err("nothing to seal: give a message in quotes");
    if (f.pass != null) {
      const work = Number.isInteger(f.work) ? f.work : WORK;
      say(["dm", 'seal --pass "***" "'], ["cr", message], ["dm", `"  · scrypt 2^${work}`]);
      await yieldFrame();
      LAST = await call("seal_passphrase", f.pass, message, work);
    } else if (f.me || f.to.length > 0) {
      if (f.me && !KEY) return err("no key yet: run keygen first");
      const keys = [...f.to, ...(f.me ? [KEY.public] : [])];
      say(["dm", "seal to "], ["cm", keys.map((k) => `${k.slice(0, 12)}…`).join(", ")], ["dm", ' "'], ["cr", message], ["dm", '"']);
      LAST = await call("seal_to", keys.join(" "), message);
    } else {
      return err('seal needs --pass "PW", --to age1…, or --me');
    }
    line(["ok", "sealed →"]);
    printFile(LAST);
    line(["dm", "next: "], ["cr", "inspect"], ["dm", " to read its header, or open it."]);
  },
  async open(args) {
    if (!LAST) return err("nothing to open: seal something first");
    const f = flags(args);
    let plain;
    if (f.pass != null) {
      say(["dm", 'open --pass "***"']);
      await yieldFrame();
      plain = await call("open_passphrase", f.pass, LAST);
    } else if (f.with) {
      say(["dm", "open --with "], ["am", `${f.with.slice(0, 20)}…`]);
      plain = await call("open_with", f.with, LAST);
    } else if (f.me) {
      if (!KEY) return err("no key: run keygen first");
      say(["dm", "open --me"]);
      plain = await call("open_with", KEY.secret, LAST);
    } else {
      return err('open needs --pass "PW", --with AGE-SECRET-KEY-1…, or --me');
    }
    line(["ok", "opened → "], ["cr", plain]);
  },
  async inspect() {
    if (!LAST) return err("nothing to inspect: seal something first");
    const view = await call("inspect", LAST);
    say(["dm", "inspect"]);
    for (const l of view.header.trimEnd().split("\n")) row("file", ["cm", l]);
    for (const s of view.stanzas) {
      line(["dm", `  stanza ${s.kind}: ${s.args.length} argument${s.args.length === 1 ? "" : "s"}, a ${s.body}-byte wrapped file key`]);
    }
    line(["dm", `  payload: ${view.payload} bytes (a 16-byte nonce, then chunks with 16-byte tags) · file: ${view.bytes} bytes`]);
  },
};

async function run(raw) {
  const text = raw.trim();
  if (!text) return;
  const [name, ...args] = tokenize(text);
  const command = CMDS[name];
  if (!command) {
    say(["dm", text]);
    return err(`unknown command: ${name}  (try "help")`);
  }
  if (!["seal", "open", "inspect"].includes(name)) say(["dm", text]);
  try {
    await command(args);
  } catch (e) {
    err(e.message || String(e));
  }
}

const form = document.getElementById("cform");
const input = document.getElementById("cmd");
form.addEventListener("submit", (e) => {
  e.preventDefault();
  run(input.value);
  input.value = "";
});
for (const b of document.querySelectorAll("#quick button")) {
  b.addEventListener("click", () => run(b.dataset.c));
}

line(["dm", "moonseal · a sealed file is a header of stanzas over a streaming payload."]);
line(["dm", "Type "], ["cm", "help"], ["dm", " to see every command, or "], ["cm", "install"], ["dm", " to begin."]);
engine.catch(() => err("the engine did not load: build it with moon build --target js --release src/examples/browser"));
