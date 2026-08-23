import { describe, expect, it } from "vitest";
import { PolicyError, SecurityPolicy, type SecurityConfig } from "../src/security.js";

function makePolicy(overrides: Partial<SecurityConfig> = {}): SecurityPolicy {
  return new SecurityPolicy({
    mode: "read-only",
    namespaceAllowlist: [],
    protectedNamespaces: ["kube-system", "kube-public", "kube-node-lease"],
    contextAllowlist: [],
    allowDelete: false,
    allowApply: false,
    allowExec: false,
    dryRun: false,
    auditLog: false,
    ...overrides,
  });
}

describe("capability gating by mode", () => {
  it("read-only enables only read", () => {
    const p = makePolicy({ mode: "read-only" });
    expect(p.isCapabilityEnabled("read")).toBe(true);
    expect(p.isCapabilityEnabled("write")).toBe(false);
    expect(p.isCapabilityEnabled("admin")).toBe(false);
  });

  it("read-write enables read+write, not admin", () => {
    const p = makePolicy({ mode: "read-write" });
    expect(p.isCapabilityEnabled("write")).toBe(true);
    expect(p.isCapabilityEnabled("admin")).toBe(false);
  });
});

describe("guard: capability vs mode", () => {
  it("rejects scale in read-only mode", () => {
    const p = makePolicy({ mode: "read-only" });
    expect(() => p.guard({ tool: "scale_deployment", capability: "write", namespace: "app" })).toThrow(
      PolicyError,
    );
  });
});

describe("namespace allowlist", () => {
  it("blocks namespaces outside a non-empty allowlist", () => {
    const p = makePolicy({ mode: "read-write", namespaceAllowlist: ["app"] });
    expect(() => p.guard({ tool: "list_pods", capability: "read", namespace: "other" })).toThrow(
      /allowlist/,
    );
    expect(() => p.guard({ tool: "list_pods", capability: "read", namespace: "app" })).not.toThrow();
  });
});

describe("protected namespaces", () => {
  it("allows reading kube-system", () => {
    const p = makePolicy({ mode: "admin" });
    expect(() => p.guard({ tool: "list_pods", capability: "read", namespace: "kube-system" })).not.toThrow();
  });

  it("blocks writing to kube-system even in admin mode", () => {
    const p = makePolicy({ mode: "admin", allowDelete: true });
    expect(() =>
      p.guard({ tool: "scale_deployment", capability: "write", namespace: "kube-system" }),
    ).toThrow(/protected/);
  });
});

describe("context allowlist", () => {
  it("blocks contexts outside a non-empty allowlist", () => {
    const p = makePolicy({ contextAllowlist: ["staging"] });
    expect(() => p.guard({ tool: "list_pods", capability: "read", context: "prod" })).toThrow(
      /allowlist/,
    );
  });
});

describe("destructive / apply / exec gating", () => {
  it("blocks delete without allowDelete", () => {
    const p = makePolicy({ mode: "admin" });
    expect(() =>
      p.guard({ tool: "delete_resource", capability: "admin", namespace: "app", destructive: true }),
    ).toThrow(/ALLOW_DELETE/);
  });

  it("blocks apply without allowApply", () => {
    const p = makePolicy({ mode: "read-write" });
    expect(() =>
      p.guard({ tool: "apply_manifest", capability: "write", namespace: "app", requiresApply: true }),
    ).toThrow(/ALLOW_APPLY/);
  });

  it("blocks exec without allowExec", () => {
    const p = makePolicy({ mode: "admin" });
    expect(() =>
      p.guard({ tool: "exec_in_pod", capability: "admin", namespace: "app", requiresExec: true }),
    ).toThrow(/ALLOW_EXEC/);
  });

  it("execEnabled requires both admin mode and the exec flag", () => {
    expect(makePolicy({ mode: "admin", allowExec: false }).execEnabled).toBe(false);
    expect(makePolicy({ mode: "read-write", allowExec: true }).execEnabled).toBe(false);
    expect(makePolicy({ mode: "admin", allowExec: true }).execEnabled).toBe(true);
  });
});

describe("dry run", () => {
  it("flags writes but not reads", () => {
    const p = makePolicy({ mode: "read-write", dryRun: true });
    expect(p.guard({ tool: "list_pods", capability: "read", namespace: "app" }).dryRun).toBe(false);
    expect(p.guard({ tool: "scale_deployment", capability: "write", namespace: "app" }).dryRun).toBe(true);
  });
});
