/**
 * Strip Secret values so credentials never reach the model.
 *
 * Pure, no I/O — unit-tested directly in test/redact.test.ts. Applied by K8sClient to every path
 * that can return a Secret object (`getObject`, `listObjects`), so any kind supplied by the caller
 * (including the generic get_resource / list_resources tools) is covered, not just a hardcoded list
 * of known-sensitive kinds.
 */

export interface RedactableObject {
  kind?: string;
  data?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface RedactableList<T extends RedactableObject = RedactableObject> {
  items?: T[];
  [key: string]: unknown;
}

/** Replace a Secret's base64 `data` values with a size marker; keep the keys so shape is visible. */
export function redactSecret<T extends RedactableObject>(obj: T): T {
  if (!obj || obj.kind !== "Secret" || !obj.data || typeof obj.data !== "object") return obj;
  const data = obj.data as Record<string, string>;
  const redacted: Record<string, string> = {};
  for (const key of Object.keys(data)) {
    redacted[key] = `<redacted, ${Buffer.from(data[key] ?? "", "base64").length} bytes>`;
  }
  return { ...obj, data: redacted };
}

/** Apply `redactSecret` to every item of a Kubernetes list response. */
export function redactList<T extends RedactableObject>(list: RedactableList<T>): RedactableList<T> {
  if (!list || !Array.isArray(list.items)) return list;
  return { ...list, items: list.items.map(redactSecret) };
}
