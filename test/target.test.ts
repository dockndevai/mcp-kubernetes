import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { KubernetesObjectApi } from "@kubernetes/client-node";
import type { AppConfig } from "../src/config.js";
import { K8sClient } from "../src/k8s/client.js";
import { buildServer } from "../src/server.js";

const config = (allowlist: string[] = []): AppConfig => ({
  connection: { inCluster: false },
  security: {
    mode: "admin",
    namespaceAllowlist: allowlist,
    protectedNamespaces: ["kube-system"],
    contextAllowlist: [],
    allowDelete: true,
    allowApply: true,
    allowExec: true,
    dryRun: false,
    auditLog: false,
    requireHumanApproval: false,
  },
});

async function connect(allowlist: string[] = []) {
  const { server } = buildServer(config(allowlist));
  const client = new Client({ name: "t", version: "0" }, { capabilities: {} });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  return client;
}

const text = (r: unknown) => ((r as { content: Array<{ text: string }> }).content[0]?.text ?? "");
const isError = (r: unknown) => (r as { isError?: boolean }).isError === true;

afterEach(() => vi.restoreAllMocks());

/** Stubs every backend call so a test can assert whether the policy let the call reach the cluster. */
function stubBackend(...args: [defaultNamespace?: string | undefined]) {
  const defaultNamespace = args.length === 0 ? "default" : args[0];
  return {
    del: vi.spyOn(K8sClient.prototype, "deleteObject").mockResolvedValue({} as never),
    get: vi.spyOn(K8sClient.prototype, "getObject").mockResolvedValue({ kind: "Whatever" } as never),
    apply: vi.spyOn(K8sClient.prototype, "applyObject").mockResolvedValue({ action: "created" }),
    version: vi.spyOn(K8sClient.prototype, "objectVersion").mockResolvedValue("u-1@1"),
    effective: vi.spyOn(K8sClient.prototype, "effectiveNamespace").mockResolvedValue(defaultNamespace),
  };
}

describe("delete_resource: a Namespace's own name is the namespace the policy checks", () => {
  it("refuses to delete a protected namespace when `namespace` is omitted", async () => {
    const b = stubBackend();
    const res = await (await connect()).callTool({
      name: "delete_resource",
      arguments: { apiVersion: "v1", kind: "Namespace", name: "kube-system" },
    });
    expect(isError(res)).toBe(true);
    expect(text(res)).toMatch(/protected/);
    expect(b.del).not.toHaveBeenCalled();
  });

  it("is not fooled by a harmless `namespace` argument next to a protected name", async () => {
    const b = stubBackend();
    const res = await (await connect()).callTool({
      name: "delete_resource",
      arguments: { apiVersion: "v1", kind: "Namespace", name: "kube-system", namespace: "scratch" },
    });
    expect(isError(res)).toBe(true);
    expect(text(res)).toMatch(/protected/);
    expect(b.del).not.toHaveBeenCalled();
  });

  it("enforces the namespace allowlist on the namespace being deleted", async () => {
    const b = stubBackend();
    const c = await connect(["shop"]);
    const denied = await c.callTool({ name: "delete_resource", arguments: { apiVersion: "v1", kind: "Namespace", name: "billing" } });
    expect(isError(denied)).toBe(true);
    expect(text(denied)).toMatch(/allowlist/);
    expect(b.del).not.toHaveBeenCalled();
    // Control: an allowed, unprotected namespace still deletes.
    const ok = await c.callTool({ name: "delete_resource", arguments: { apiVersion: "v1", kind: "Namespace", name: "shop" } });
    expect(text(ok)).toContain('"deleted": true');
    expect(b.del).toHaveBeenCalledTimes(1);
  });
});

describe("a namespaced kind with no namespace targets the client's default namespace, and the policy checks that", () => {
  for (const ns of [undefined, ""]) {
    it(`delete_resource Pod with namespace=${JSON.stringify(ns)} is refused when the default namespace is protected`, async () => {
      const b = stubBackend("kube-system");
      const res = await (await connect()).callTool({
        name: "delete_resource",
        arguments: { apiVersion: "v1", kind: "Pod", name: "coredns", ...(ns === undefined ? {} : { namespace: ns }) },
      });
      expect(isError(res)).toBe(true);
      expect(text(res)).toMatch(/protected/);
      expect(b.del).not.toHaveBeenCalled();
    });
  }

  it("delete_resource is refused when the default namespace is outside the allowlist", async () => {
    const b = stubBackend("default");
    const res = await (await connect(["shop"])).callTool({
      name: "delete_resource",
      arguments: { apiVersion: "apps/v1", kind: "Deployment", name: "web" },
    });
    expect(isError(res)).toBe(true);
    expect(text(res)).toMatch(/allowlist/);
    expect(b.del).not.toHaveBeenCalled();
  });

  it("a cluster-scoped kind (no default namespace) is not affected", async () => {
    const b = stubBackend(undefined);
    const res = await (await connect(["shop"])).callTool({
      name: "delete_resource",
      arguments: { apiVersion: "rbac.authorization.k8s.io/v1", kind: "ClusterRole", name: "tmp" },
    });
    expect(text(res)).toContain('"deleted": true');
    expect(b.del).toHaveBeenCalledTimes(1);
  });

  it("an explicit namespace is used as given (no discovery needed)", async () => {
    const b = stubBackend("kube-system");
    const res = await (await connect()).callTool({
      name: "delete_resource",
      arguments: { apiVersion: "v1", kind: "Pod", name: "web-0", namespace: "shop" },
    });
    expect(text(res)).toContain('"deleted": true');
    expect(b.effective).not.toHaveBeenCalled();
  });
});

describe("get_resource honours the namespace allowlist for the same cases", () => {
  it("reading a Namespace outside the allowlist is refused", async () => {
    const b = stubBackend();
    const res = await (await connect(["shop"])).callTool({
      name: "get_resource",
      arguments: { apiVersion: "v1", kind: "Namespace", name: "billing" },
    });
    expect(isError(res)).toBe(true);
    expect(text(res)).toMatch(/allowlist/);
    expect(b.get).not.toHaveBeenCalled();
  });

  it("a namespaced kind with no namespace is checked against the default namespace", async () => {
    const b = stubBackend("default");
    const res = await (await connect(["shop"])).callTool({
      name: "get_resource",
      arguments: { apiVersion: "v1", kind: "ConfigMap", name: "cfg" },
    });
    expect(isError(res)).toBe(true);
    expect(text(res)).toMatch(/allowlist/);
    expect(b.get).not.toHaveBeenCalled();
  });

  it("reading a protected namespace is still allowed (protection is for mutation)", async () => {
    const b = stubBackend();
    const res = await (await connect()).callTool({
      name: "get_resource",
      arguments: { apiVersion: "v1", kind: "Namespace", name: "kube-system" },
    });
    expect(isError(res)).toBe(false);
    expect(b.get).toHaveBeenCalledTimes(1);
  });
});

describe("apply_manifest checks the namespace the object will really land in", () => {
  it("refuses to apply a Namespace manifest named after a protected namespace", async () => {
    const b = stubBackend();
    const res = await (await connect()).callTool({
      name: "apply_manifest",
      arguments: { manifest: { apiVersion: "v1", kind: "Namespace", metadata: { name: "kube-system", labels: { x: "y" } } } },
    });
    expect(isError(res)).toBe(true);
    expect(text(res)).toMatch(/protected/);
    expect(b.apply).not.toHaveBeenCalled();
  });

  for (const ns of [undefined, ""]) {
    it(`refuses a namespaced manifest with metadata.namespace=${JSON.stringify(ns)} when the default namespace is protected`, async () => {
      const b = stubBackend("kube-system");
      const res = await (await connect()).callTool({
        name: "apply_manifest",
        arguments: {
          manifest: { apiVersion: "v1", kind: "ConfigMap", metadata: { name: "cfg", ...(ns === undefined ? {} : { namespace: ns }) } },
        },
      });
      expect(isError(res)).toBe(true);
      expect(text(res)).toMatch(/protected/);
      expect(b.apply).not.toHaveBeenCalled();
    });
  }

  it("still applies into an allowed namespace (control)", async () => {
    const b = stubBackend();
    const res = await (await connect(["shop"])).callTool({
      name: "apply_manifest",
      arguments: { manifest: { apiVersion: "v1", kind: "ConfigMap", metadata: { name: "cfg", namespace: "shop" } } },
    });
    expect(text(res)).toContain('"applied": true');
    expect(b.apply).toHaveBeenCalledTimes(1);
  });
});

describe("apiVersion is validated before it can reach a request path", () => {
  for (const apiVersion of ["v1/../../x#", "v1?x=1", "../v1", "a/b/c", ""]) {
    it(`delete_resource rejects apiVersion ${JSON.stringify(apiVersion)}`, async () => {
      const b = stubBackend();
      const res = await (await connect()).callTool({
        name: "delete_resource",
        arguments: { apiVersion, kind: "Pod", name: "web-0", namespace: "shop" },
      });
      expect(isError(res)).toBe(true);
      expect(text(res)).toMatch(/apiVersion/);
      expect(b.del).not.toHaveBeenCalled();
    });
  }
});

describe("K8sClient.effectiveNamespace", () => {
  function clientWithContextNamespace(ns: string | undefined): K8sClient {
    const dir = mkdtempSync(join(tmpdir(), "k8s-target-"));
    const file = join(dir, "kubeconfig");
    writeFileSync(
      file,
      [
        "apiVersion: v1",
        "kind: Config",
        "clusters: [{name: c, cluster: {server: 'https://127.0.0.1:1'}}]",
        `contexts: [{name: x, context: {cluster: c, user: u${ns ? `, namespace: ${ns}` : ""}}}]`,
        "users: [{name: u, user: {token: t}}]",
        "current-context: x",
      ].join("\n"),
    );
    return new K8sClient({ inCluster: false, kubeconfigPath: file });
  }

  it("returns the kube-config context's namespace for a namespaced kind, 'default' when it sets none", async () => {
    vi.spyOn(KubernetesObjectApi.prototype as never, "resource").mockResolvedValue({ name: "pods", kind: "Pod", namespaced: true } as never);
    expect(await clientWithContextNamespace("team-a").effectiveNamespace("v1", "Pod")).toBe("team-a");
    expect(await clientWithContextNamespace(undefined).effectiveNamespace("v1", "Pod")).toBe("default");
  });

  it("returns undefined for a cluster-scoped kind and throws for an unknown one", async () => {
    const spy = vi.spyOn(KubernetesObjectApi.prototype as never, "resource");
    spy.mockResolvedValue({ name: "nodes", kind: "Node", namespaced: false } as never);
    expect(await clientWithContextNamespace("team-a").effectiveNamespace("v1", "Node")).toBeUndefined();
    spy.mockResolvedValue(undefined as never);
    await expect(clientWithContextNamespace("team-a").effectiveNamespace("v1", "Nope")).rejects.toThrow(/Unrecognized/);
  });
});
