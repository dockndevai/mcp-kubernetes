import type { K8sClient } from "../k8s/client.js";
import type { SecurityPolicy } from "../security.js";

/** `v1`, `apps/v1`, `networking.k8s.io/v1beta1`: a DNS-style group, then a version. Nothing that can alter a request path. */
const API_VERSION = /^([a-z0-9]([-a-z0-9.]*[a-z0-9])?\/)?[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

export function assertApiVersion(apiVersion: string): void {
  if (!API_VERSION.test(apiVersion)) {
    throw new Error(`Invalid apiVersion '${apiVersion}': expected 'v1' or '<group>/<version>' (e.g. apps/v1).`);
  }
}

/**
 * The namespace an object-addressed call (get/delete/apply by apiVersion + kind + name) will really act on, which is
 * what the policy must check. It is NOT always the `namespace` argument:
 *  - a Namespace is cluster-scoped, so its own name is the namespace (and a `namespace` argument is ignored by the API);
 *  - a namespaced kind with no (or an empty) namespace lands in the kube-config context's default namespace;
 *  - a cluster-scoped kind targets no namespace.
 */
export async function targetNamespace(
  client: K8sClient,
  policy: SecurityPolicy,
  t: { apiVersion?: string; kind?: string; name?: string; namespace?: string; context?: string },
): Promise<string | undefined> {
  if (t.apiVersion !== undefined) assertApiVersion(t.apiVersion);
  if (!t.apiVersion || !t.kind) return t.namespace || undefined; // incomplete: the caller rejects it
  if (t.apiVersion === "v1" && t.kind === "Namespace") return t.name;
  if (t.namespace) return t.namespace;
  // A disallowed context is refused by the policy; do not talk to that cluster just to resolve a namespace.
  if (t.context !== undefined && !policy.isContextAllowed(t.context)) return undefined;
  return client.effectiveNamespace(t.apiVersion, t.kind, t.context);
}
