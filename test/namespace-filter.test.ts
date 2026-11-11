import { describe, expect, it } from "vitest";
import { SecurityPolicy, type SecurityConfig } from "../src/security.js";
import { filterNamespaceAllowed } from "../src/tools/types.js";

function makePolicy(overrides: Partial<SecurityConfig> = {}): SecurityPolicy {
  return new SecurityPolicy({
    mode: "read-only",
    namespaceAllowlist: [],
    protectedNamespaces: [],
    contextAllowlist: [],
    allowDelete: false,
    allowApply: false,
    allowExec: false,
    dryRun: false,
    auditLog: false,
    ...overrides,
  });
}

describe("filterNamespaceAllowed", () => {
  it("passes every item through when the allowlist is empty", () => {
    const list = { items: [{ metadata: { namespace: "app" } }, { metadata: { namespace: "kube-system" } }] };
    const result = filterNamespaceAllowed(list, makePolicy());
    expect(result.items).toHaveLength(2);
  });

  it("drops items outside a non-empty namespace allowlist, e.g. a namespace-less list_resources call", () => {
    const policy = makePolicy({ namespaceAllowlist: ["app"] });
    const list = {
      items: [
        { metadata: { name: "a", namespace: "app" } },
        { metadata: { name: "b", namespace: "kube-system" } },
        { metadata: { name: "c", namespace: "other" } },
      ],
    };
    const result = filterNamespaceAllowed(list, policy);
    expect(result.items?.map((i) => i.metadata?.namespace)).toEqual(["app"]);
  });

  it("always keeps cluster-scoped items (no metadata.namespace), e.g. Nodes", () => {
    const policy = makePolicy({ namespaceAllowlist: ["app"] });
    const list = { items: [{ metadata: { name: "node-1" } }] };
    expect(filterNamespaceAllowed(list, policy).items).toHaveLength(1);
  });

  it("leaves a response with no items array unchanged", () => {
    const notAList = { kind: "Status" };
    expect(filterNamespaceAllowed(notAList, makePolicy({ namespaceAllowlist: ["app"] }))).toEqual(notAList);
  });
});
