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
