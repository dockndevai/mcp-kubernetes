/**
 * Secret redaction: credentials must never reach the model. A Secret's values live in `data` (base64) and
 * `stringData` (plain), and `kubectl apply` also stores the whole object, values included, in the
 * `kubectl.kubernetes.io/last-applied-configuration` annotation. Keys and sizes are kept so the model can still
 * see what a Secret holds.
 */

const LAST_APPLIED = "kubectl.kubernetes.io/last-applied-configuration";

type Obj = Record<string, unknown>;

/** What `redactSecret` is told when the caller already knows the object is a Secret. */
const SECRET_KIND = "Secret";

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
export function redactUrlPasswords(line: string): string {
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
const KEY_WORD_PATTERNS = [
  "password", "passwd", "passphrase",
  "x[_-]?amz[_-]?signature",
  "secret[_-]?(?:access[_-]?)?key", "secret",
  "token", "credentials?", "authorization",
  "(?:api|access|private|signing|encryption|master|account|auth|primary|secondary)[_-]?key",
  "sig",
];
const KEY_WORDS = new RegExp(KEY_WORD_PATTERNS.join("|"), "gi");
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

// ---------------------------------------------------------------------------------------------------------------
// Object redaction (workload specs, ConfigMaps, Routes, events): best effort, mostly BY NAME.
//
// `redactSecret` above is unconditional: Secrets never reach the model. Other objects can carry credentials too, and
// they are not shaped like Secrets, so `redactObject` walks the whole (JSON) object and masks, in order:
//   1. a nested Secret anywhere (a List, a Template's `objects`): always, even when heuristics are off
//   2. `env` entries (containers, initContainers, ephemeralContainers, and every pod template under Deployments,
//      StatefulSets, DaemonSets, ReplicaSets, Jobs, CronJobs' jobTemplate, custom resources, ...), `httpHeaders` and
//      `parameters` entries: the `value` of an entry whose `name` is secret-shaped (see isSecretName) becomes
//      `<redacted, N bytes>`; any other value is still scrubbed with redactLogText (URL passwords, token shapes,
//      key=value pairs, PEM private keys). `valueFrom` references are kept (a secretKeyRef names a Secret, it does
//      not hold the value).
//   3. `command` / `args` string lists: scrubbed with redactLogText, and the value after a secret-shaped flag
//      (`--password hunter2`) is masked
//   4. ConfigMap `data` / `binaryData`: an entry whose KEY is secret-shaped is masked; any other value is scrubbed with
//      redactLogText (binaryData is decoded first and masked as a whole when the text inside has a credential)
//   5. Route `tls.key` / `spec.tls.key` (OpenShift): masked; the certificate fields are scrubbed (a private key
//      pasted into one is masked, a public certificate is left readable)
//   6. BuildConfig webhook trigger `secret`s; Event `message`s (scrubbed with redactLogText)
//   7. the `kubectl.kubernetes.io/last-applied-configuration` annotation, which holds a copy of the manifest: parsed
//      and redacted like any other object (or replaced by `<redacted>` when it is not JSON)
//   8. passwords inside any `scheme://user:password@host` URL in any string
//
// Everything after step 1 is HEURISTIC and can be turned off by the operator (`redactObjects: false`). A secret
// stored under an innocuous name with an innocuous shape (`CONFIG=<random string>`, a password in a ConfigMap key
// called `app.properties` that is not written as key=value, an opaque binary blob under a neutral name) is NOT
// caught. Names are preferred over values, and over-redaction of a name like `GOOGLE_APPLICATION_CREDENTIALS` (a path)
// is accepted: the cost is a missing value, not a leaked credential.
// ---------------------------------------------------------------------------------------------------------------

const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);

/** Last part of an env var / config key name that makes it secret-shaped. Built from the same list as redactKeyValues. */
const SECRET_NAME = new RegExp(
  `(?:${[
    ...KEY_WORD_PATTERNS.filter((p) => p !== "sig"),
    "secret[_-]?key[_-]?base", "key", "auth", "bearer",
    "connection[_-]?string", "conn[_-]?str",
    "dockerconfigjson", "dockercfg", "kubeconfig", "netrc",
    "(?:^|[^a-z])(?:pass|pwd|dsn|jwt)",
  ].join("|")})s?$`,
  "i",
);

/** Whether an env var / header / parameter / config key NAME says its value is a credential (`DB_PASSWORD`, `apiKey`, `tls.key`). */
export function isSecretName(name: string): boolean {
  return SECRET_NAME.test(name.trim().slice(-256));
}

const CONFIG_FILE_EXT = /\.(?:json|ya?ml|properties|env|txt|conf|cfg|ini|xml|toml)$/i;
const SECRET_FILE = /(?:\.(?:p12|pfx|jks|keystore)|^id_(?:rsa|dsa|ecdsa|ed25519))$/i;
/** ConfigMap keys are often file names: `credentials.json`, `db.password`, `server.key`, `keystore.p12`, `id_rsa`. */
function isSecretConfigKey(key: string): boolean {
  return isSecretName(key.replace(CONFIG_FILE_EXT, "")) || SECRET_FILE.test(key);
}

const PLACEHOLDER = /^<redacted, \d+ bytes>$/;
function placeholder(v: string, base64 = false): string {
  if (PLACEHOLDER.test(v)) return v;
  return `<redacted, ${base64 ? Buffer.from(v, "base64").length : Buffer.byteLength(v)} bytes>`;
}

function decodeText(b: Buffer): string | undefined {
  if (b.includes(0)) return undefined;
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(b);
  } catch {
    return undefined;
  }
}

function redactConfigData(data: Obj, binary: boolean): Obj {
  const out: Obj = {};
  for (const [k, v] of Object.entries(data)) {
    if (typeof v !== "string") out[k] = v;
    else if (isSecretConfigKey(k)) out[k] = placeholder(v, binary);
    else if (!binary) out[k] = redactLogText(v);
    else {
      const text = decodeText(Buffer.from(v, "base64"));
      out[k] = text !== undefined && redactLogText(text) !== text ? placeholder(v, true) : v;
    }
  }
  return out;
}

function redactTls(tls: unknown): unknown {
  if (!isObj(tls)) return tls;
  const out: Obj = { ...tls };
  if (typeof out.key === "string") out.key = placeholder(out.key);
  for (const f of ["certificate", "caCertificate", "destinationCACertificate"]) {
    if (typeof out[f] === "string") out[f] = redactLogText(out[f] as string);
  }
  return out;
}

const WEBHOOK_TRIGGERS = ["github", "gitlab", "bitbucket", "generic"];
function redactTriggers(triggers: unknown): unknown {
  if (!Array.isArray(triggers)) return triggers;
  return triggers.map((t) => {
    if (!isObj(t)) return t;
    const out: Obj = { ...t };
    for (const w of WEBHOOK_TRIGGERS) {
      const hook = out[w];
      if (isObj(hook) && typeof hook.secret === "string") out[w] = { ...hook, secret: placeholder(hook.secret) };
    }
    return out;
  });
}

/** Name/value lists (`env`, `httpHeaders`, `parameters`). Entries of any other shape go through `other`. */
function redactNameValues(list: unknown[], other: (e: unknown) => unknown): unknown[] {
  return list.map((e) => {
    if (!isObj(e) || typeof e.name !== "string" || typeof e.value !== "string") return other(e);
    return { ...e, value: isSecretName(e.name) ? placeholder(e.value) : redactLogText(e.value) };
  });
}

/** `command` / `args`: each element scrubbed, and the element after a secret-shaped flag (`--password x`) masked. */
function redactArgv(list: string[]): string[] {
  let maskNext = false;
  return list.map((a) => {
    if (maskNext) {
      maskNext = false;
      if (!a.startsWith("-")) return placeholder(a);
    }
    const flag = /^--?([A-Za-z0-9][A-Za-z0-9_.-]*)$/.exec(a);
    if (flag && isSecretName(flag[1])) maskNext = true;
    return redactLogText(a);
  });
}

const LAST_APPLIED_KEY = "kubectl.kubernetes.io/last-applied-configuration";
const DEEP = "<redacted: nested too deep>";
const MAX_DEPTH = 64;

/** `kind` / requested kind in one comparable form: lower case, singular (`configmaps` and `ConfigMap` are the same). */
const kindKey = (k: string | undefined): string | undefined => k?.toLowerCase().replace(/s$/, "");

function kindRules(o: Obj, kind: string | undefined): void {
  switch (kind) {
    case "configmap":
      if (isObj(o.data)) o.data = redactConfigData(o.data, false);
      if (isObj(o.binaryData)) o.binaryData = redactConfigData(o.binaryData, true);
      break;
    case "route":
      if (o.tls !== undefined) o.tls = redactTls(o.tls);
      if (isObj(o.spec) && o.spec.tls !== undefined) o.spec = { ...o.spec, tls: redactTls(o.spec.tls) };
      break;
    case "buildconfig":
      if (isObj(o.spec) && o.spec.triggers !== undefined) o.spec = { ...o.spec, triggers: redactTriggers(o.spec.triggers) };
      break;
    case "event":
      if (typeof o.message === "string") o.message = redactLogText(o.message);
      break;
  }
}

function walk(node: unknown, hint: string | undefined, heuristics: boolean, depth: number): unknown {
  if (typeof node === "string") return heuristics ? redactUrlPasswords(node) : node;
  if (Array.isArray(node)) {
    if (depth > MAX_DEPTH) return DEEP;
    return node.map((x) => walk(x, undefined, heuristics, depth + 1));
  }
  if (!isObj(node)) return node;
  if (depth > MAX_DEPTH) return DEEP;
  const ownKind = typeof node.kind === "string" ? kindKey(node.kind) : undefined;
  // A list: its items usually omit `kind`, so they take the list's (or the requested) kind.
  const isList = Array.isArray(node.items) && (ownKind === undefined || ownKind === "list" || ownKind.endsWith("list"));
  const itemHint = isList ? (ownKind && ownKind !== "list" ? ownKind.slice(0, -4) : hint) : undefined;
  const kind = isList ? undefined : (ownKind ?? hint);
  if (kind === "secret") return redactSecret(node, SECRET_KIND);
  const out: Obj = { ...node };
  if (heuristics) kindRules(out, kind);
  for (const [k, v] of Object.entries(out)) {
    const child = (x: unknown) => walk(x, undefined, heuristics, depth + 1);
    if (k === "items" && isList && Array.isArray(v)) {
      out[k] = v.map((i) => walk(i, itemHint, heuristics, depth + 1));
    } else if (heuristics && Array.isArray(v) && (k === "env" || k === "httpHeaders" || k === "parameters")) {
      out[k] = redactNameValues(v, child);
    } else if (heuristics && Array.isArray(v) && (k === "command" || k === "args") && v.every((x) => typeof x === "string")) {
      out[k] = redactArgv(v as string[]);
    } else if (heuristics && k === "annotations" && isObj(v) && typeof v[LAST_APPLIED_KEY] === "string") {
      out[k] = { ...(child(v) as Obj), [LAST_APPLIED_KEY]: redactLastApplied(v[LAST_APPLIED_KEY] as string) };
    } else {
      out[k] = child(v);
    }
  }
  return out;
}

function redactLastApplied(json: string): string {
  try {
    const parsed: unknown = JSON.parse(json);
    if (parsed && typeof parsed === "object") return JSON.stringify(walk(parsed, undefined, true, 0));
  } catch {
    /* not JSON: fall through */
  }
  return "<redacted>";
}

/**
 * Returns a copy of `obj` (a Kubernetes object or list) that is safe to hand to the model: Secrets are always
 * redacted (nested ones too); with `heuristics` (the default) the by-name redaction described above is applied as well.
 * `requestedKind` is the kind the caller asked for (`ConfigMap`, `configmaps`), for responses that omit `kind`.
 * The input is not mutated; Date and class instances are normalised to plain JSON, which is what is returned to the model anyway.
 */
export function redactObject<T>(obj: T, requestedKind?: string, heuristics = true): T {
  if (!obj || typeof obj !== "object") return obj;
  return walk(JSON.parse(JSON.stringify(obj)), kindKey(requestedKind), heuristics, 0) as T;
}
