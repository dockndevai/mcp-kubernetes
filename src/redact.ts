/**
 * Secret redaction: credentials must never reach the model. A Secret's values live in `data` (base64) and
 * `stringData` (plain), and `kubectl apply` also stores the whole object, values included, in the
 * `kubectl.kubernetes.io/last-applied-configuration` annotation. Keys and sizes are kept so the model can still
 * see what a Secret holds.
 */

const LAST_APPLIED = "kubectl.kubernetes.io/last-applied-configuration";

type Obj = Record<string, unknown>;

function redactValues(values: unknown, decode: (v: string) => number): Obj | undefined {
  if (!values || typeof values !== "object") return undefined;
  const out: Obj = {};
  for (const [k, v] of Object.entries(values as Obj)) out[k] = `<redacted, ${typeof v === "string" ? decode(v) : 0} bytes>`;
  return out;
}

/**
 * Returns a copy of `obj` with Secret values removed. Applies when the object is a Secret (by its own `kind`, or by the
 * `kind` the caller asked for, since the response may omit it) or a SecretList; any other object is returned as is.
 */
export function redactSecret<T>(obj: T, requestedKind?: string): T {
  if (!obj || typeof obj !== "object") return obj;
  const o = obj as Obj;
  if (o.kind === "SecretList" && Array.isArray(o.items)) {
    return { ...o, items: o.items.map((i) => redactSecret(i, "Secret")) } as T;
  }
  if (o.kind !== "Secret" && requestedKind !== "Secret") return obj;
  const out: Obj = { ...o };
  const data = redactValues(o.data, (v) => Buffer.from(v, "base64").length);
  if (data) out.data = data;
  const stringData = redactValues(o.stringData, (v) => Buffer.byteLength(v));
  if (stringData) out.stringData = stringData;
  const md = o.metadata as Obj | undefined;
  const ann = md?.annotations as Obj | undefined;
  if (md && ann && LAST_APPLIED in ann) {
    out.metadata = { ...md, annotations: { ...ann, [LAST_APPLIED]: "<redacted>" } };
  }
  return out as T;
}

// ---------------------------------------------------------------------------------------------------------------
// Log / exec output redaction (best effort).
//
// Pod logs and exec output are whatever the workload wrote, so a workload that logs a credential would hand it to
// the model. `redactLogText` masks the credential shapes listed below. It is HEURISTIC defence in depth, not a
// guarantee: a secret with no recognisable shape and no telling key name (a bare random password, a raw AWS secret
// access key on its own) is NOT caught.
//
// Design: line oriented, and every pass is linear in the input. There is no regex with a leading unbounded
// quantifier or nested quantifiers; each regex starts with a literal and has at most one unbounded run over a class
// that cannot overlap what follows it, and the key/value and URL passes are plain index scans. Passes, in order:
//   1. PEM private-key blocks (multi-line; also an unterminated block and a block whose BEGIN line was cut off by tail)
//   2. credentials inside URLs (scheme://user:PASSWORD@host)
//   3. key/value pairs whose key ENDS in a secret-ish word (password=…, "client_secret": "…", Authorization: Bearer …)
//   4. a bare `Bearer <token>`
//   5. well-known token shapes (JWT incl. Kubernetes service-account tokens, OpenShift sha256~ tokens, AWS access key
//      ids, GCP API keys / OAuth tokens, GitHub / GitLab / Slack / Stripe / npm / Vault / SendGrid tokens)
// ---------------------------------------------------------------------------------------------------------------

const MARK = "[REDACTED]";
const PEM_MARK = "[REDACTED PRIVATE KEY]";

const PEM_BEGIN = /-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----/g;
const PEM_END = /-----END [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----/g;
const BARE_BASE64_LINE = /^[A-Za-z0-9+/]{20,}={0,2}\r?$/;

/** First match of a /g regex at or after `from`, or null. */
function findFrom(re: RegExp, line: string, from: number): RegExpExecArray | null {
  re.lastIndex = from;
  return re.exec(line);
}

/** Multi-line PEM private keys. Interior lines are dropped; the BEGIN line keeps whatever preceded the header. */
function redactPem(lines: string[]): string[] {
  const out: string[] = [];
  let inKey = false;
  for (const line of lines) {
    let pos = 0;
    let acc = "";
    if (inKey) {
      const e = findFrom(PEM_END, line, 0);
      if (!e) continue; // still inside the key: drop the line
      inKey = false;
      pos = e.index + e[0].length;
      if (line.slice(pos).trim() === "") continue;
    }
    // `b` / `e` are the next header / footer at or after `pos`; each is only searched for again once consumed, so
    // a line with many markers is still scanned once.
    let b = findFrom(PEM_BEGIN, line, pos);
    let e = findFrom(PEM_END, line, pos);
    for (;;) {
      if (e && (!b || e.index < b.index)) {
        // A footer with no header before it: `tail` cut the BEGIN line off. Drop the bare base64 body that precedes it.
        const pre = line.slice(pos, e.index);
        const bare = /^[A-Za-z0-9+/]*={0,2}\r?$/.test(pre);
        if (!acc && bare) while (out.length > 0 && BARE_BASE64_LINE.test(out[out.length - 1])) out.pop();
        acc += (bare ? "" : pre) + PEM_MARK;
        pos = e.index + e[0].length;
        e = findFrom(PEM_END, line, pos);
        continue;
      }
      if (!b) break;
      acc += line.slice(pos, b.index) + PEM_MARK;
      if (e) {
        pos = e.index + e[0].length;
        b = findFrom(PEM_BEGIN, line, pos);
        e = findFrom(PEM_END, line, pos);
        continue;
      }
      inKey = true;
      pos = line.endsWith("\r") ? line.length - 1 : line.length;
      break;
    }
    out.push(acc + line.slice(pos));
  }
  return out;
}

const isAuthorityEnd = (c: number) =>
  c === 47 /* / */ || c === 63 /* ? */ || c === 35 /* # */ || c === 34 /* " */ || c === 39 /* ' */ ||
  c === 96 /* ` */ || c === 60 /* < */ || c === 62 /* > */ || c === 92 /* \ */ || c <= 32;

/** scheme://user:PASSWORD@host -> scheme://user:[REDACTED]@host. A user without a password is left alone. */
function redactUrlPasswords(line: string): string {
  let idx = line.indexOf("://");
  if (idx < 0) return line;
  let out = "";
  let last = 0;
  while (idx !== -1) {
    const start = idx + 3;
    let j = start;
    let colon = -1;
    let at = -1;
    while (j < line.length && !isAuthorityEnd(line.charCodeAt(j))) {
      const c = line.charCodeAt(j);
      if (c === 58 /* : */ && colon === -1 && at === -1) colon = j;
      else if (c === 64 /* @ */) at = j;
      j++;
    }
    if (at !== -1 && colon !== -1 && colon < at && at - colon > 1 && !line.startsWith("[REDACTED", colon + 1)) {
      out += line.slice(last, colon + 1) + MARK;
      last = at;
    }
    idx = line.indexOf("://", j);
  }
  return last === 0 ? line : out + line.slice(last);
}

// Keywords a key must END in (so `token_count`, `secretName`, `tokenizer`, `max_tokens` are left alone).
const KEY_WORDS = new RegExp(
  [
    "password", "passwd", "passphrase",
    "x[_-]?amz[_-]?signature",
    "secret[_-]?(?:access[_-]?)?key", "secret",
    "token", "credentials?", "authorization",
    "(?:api|access|private|signing|encryption|master|account|auth|primary|secondary)[_-]?key",
    "sig",
  ].join("|"),
  "gi",
);
const isKeyChar = (ch: string | undefined) => ch !== undefined && /[A-Za-z0-9_.-]/.test(ch);
const SCHEME = /^(?:bearer|basic|digest|token|negotiate|ntlm|aws4-hmac-sha256)$/i;
const QUOTED_SCHEME = /^(?:bearer|basic|digest|token|negotiate|ntlm|aws4-hmac-sha256)[ \t]+/i;
// Values that are not secrets: placeholders, an already-redacted marker, a variable reference, or a short status word.
const BENIGN_VALUE = new RegExp(
  "^(?:(?:null|nil|none|undefined|true|false|empty|n/a|-|\\(none\\)|<none>|<nil>|<unset>|\\*+|" +
    "required|missing|invalid|incorrect|expired|mismatch|rejected|denied|failed|ok)$|\\[redacted|<redacted|" +
    "\\$(?:\\{[A-Za-z_][A-Za-z0-9_]*\\}|\\([A-Za-z_][A-Za-z0-9_]*\\)|[A-Z_][A-Z0-9_]*)$)",
  "i",
);

function unquotedEnd(line: string, from: number): number {
  let i = from;
  while (i < line.length) {
    const c = line[i];
    if (c === " " || c === "\t" || c === "\r" || c === '"' || c === "'" || c === "`" || c === "," || c === ";" || c === "&" || c === "<" || c === ">") break;
    i++;
  }
  return i;
}

/** key=value / key: value / "key": "value" / --flag value, where the key ends in a secret-ish word. */
function redactKeyValues(line: string): string {
  KEY_WORDS.lastIndex = 0;
  let out = "";
  let last = 0;
  for (let m = KEY_WORDS.exec(line); m !== null; m = KEY_WORDS.exec(line)) {
    const kStart = m.index;
    const kEnd = kStart + m[0].length;
    if (m[0].toLowerCase() === "sig" && isKeyChar(line[kStart - 1])) continue;
    // The keyword must END the key: a separator (or the key's closing quote) has to follow it directly, so
    // `token_count=5`, `secretName: x`, `tokenizer=y` and `--password-file f` are not credentials.
    let i = kEnd;
    if (line[i] === '"' || line[i] === "'") i++;
    else if (line[i] === "\\" && (line[i + 1] === '"' || line[i + 1] === "'")) i += 2;
    const afterKey = i;
    while (line[i] === " " || line[i] === "\t") i++;
    if (line[i] === ":" || line[i] === "=") {
      i++;
      if (line[i] === ">" || line[i] === "=") i++; // `=>`, `:=`, `==`
    } else {
      // `--password hunter2`: a flag followed by a space and its value.
      if (i === afterKey) continue;
      let ks = kStart;
      while (kStart - ks < 64 && isKeyChar(line[ks - 1])) ks--;
      if (!(line[ks] === "-" && line[ks + 1] === "-")) continue;
    }
    while (line[i] === " " || line[i] === "\t") i++;
    let vStart = i;
    let vEnd: number;
    let quoted = true;
    const ch = line[i];
    if (ch === undefined || ch === "\r") continue;
    if (ch === '"' || ch === "'") {
      vStart = i + 1;
      vEnd = vStart;
      while (vEnd < line.length && line[vEnd] !== ch) vEnd += line[vEnd] === "\\" ? 2 : 1;
      if (vEnd > line.length) vEnd = line.length;
    } else if (ch === "\\" && (line[i + 1] === '"' || line[i + 1] === "'")) {
      vStart = i + 2;
      const close = line.indexOf(line.slice(i, i + 2), vStart);
      vEnd = close === -1 ? line.length : close;
    } else {
      quoted = false;
      if (ch === "[" && !line.startsWith("[REDACTED", i)) vStart++; // Go-style header maps: Authorization:[Bearer abc]
      vEnd = unquotedEnd(line, vStart);
    }
    if (vEnd <= vStart) continue;
    // `Authorization: Bearer <token>`: keep the scheme, redact what follows it.
    if (quoted) {
      const sm = QUOTED_SCHEME.exec(line.slice(vStart, vEnd));
      if (sm) vStart += sm[0].length;
    } else if (SCHEME.test(line.slice(vStart, vEnd)) && (line[vEnd] === " " || line[vEnd] === "\t")) {
      const isAws = /^aws4/i.test(line.slice(vStart, vEnd));
      vStart = vEnd;
      while (line[vStart] === " " || line[vStart] === "\t") vStart++;
      vEnd = isAws ? line.length : unquotedEnd(line, vStart);
    }
    if (vEnd <= vStart) continue;
    const value = line.slice(vStart, vEnd);
    if (BENIGN_VALUE.test(value)) continue;
    out += line.slice(last, vStart) + MARK;
    last = vEnd;
    KEY_WORDS.lastIndex = vEnd;
  }
  return last === 0 ? line : out + line.slice(last);
}

const BEARER = /\b(bearer[ \t]+)([A-Za-z0-9._~+/-]+=*)/gi;
const TOKEN_RUN = /[A-Za-z0-9_.~+/-]+={0,2}/g;
const TOKEN_SHAPES: Array<[string, RegExp]> = [
  ["jwt", /^eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*$/],
  ["openshift-token", /^sha256~[A-Za-z0-9_-]{20,}={0,2}$/],
  ["aws-access-key-id", /^(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16}$/],
  ["gcp-api-key", /^AIza[A-Za-z0-9_-]{35}$/],
  ["gcp-oauth-token", /^ya29\.[A-Za-z0-9._-]{20,}$/],
  ["github-token", /^(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})$/],
  ["gitlab-token", /^glpat-[A-Za-z0-9_-]{20,}$/],
  ["slack-token", /^xox[abeprs]-[A-Za-z0-9-]{10,}$/],
  ["stripe-key", /^[sr]k_(?:live|test)_[A-Za-z0-9]{16,}$/],
  ["npm-token", /^npm_[A-Za-z0-9]{36}$/],
  ["vault-token", /^hv[sbr]\.[A-Za-z0-9_-]{20,}$/],
  ["sendgrid-key", /^SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}$/],
];

function redactTokens(line: string): string {
  line = line.replace(BEARER, (all, scheme: string, token: string) =>
    token.length >= 8 && /\d/.test(token) ? `${scheme}${MARK}` : all,
  );
  TOKEN_RUN.lastIndex = 0;
  let out = "";
  let last = 0;
  for (let m = TOKEN_RUN.exec(line); m !== null; m = TOKEN_RUN.exec(line)) {
    const t = m[0];
    if (t.length < 14) continue;
    const shape = TOKEN_SHAPES.find(([, re]) => re.test(t));
    if (!shape) continue;
    out += `${line.slice(last, m.index)}[REDACTED:${shape[0]}]`;
    last = m.index + t.length;
  }
  return last === 0 ? line : out + line.slice(last);
}

/**
 * Masks credentials in free-form text (pod logs, exec output). Best effort and heuristic: see the block comment above
 * and SECURITY.md for what is and is not caught. Pure, linear in the input, never throws, and idempotent.
 */
export function redactLogText(text: string): string {
  if (!text) return text;
  const lines = redactPem(text.split("\n"));
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (l.length < 6) continue;
    lines[i] = redactTokens(redactKeyValues(redactUrlPasswords(l)));
  }
  return lines.join("\n");
}
