import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import type { AppConfig } from "../src/config.js";
import { ApiException, KubernetesObjectApi } from "@kubernetes/client-node";
import { K8sClient, parseVersionToken, versionToken } from "../src/k8s/client.js";
import { buildServer } from "../src/server.js";

const config = (requireHumanApproval = false): AppConfig => ({
  connection: { inCluster: false },
  security: {
    mode: "admin",
    namespaceAllowlist: [],
    protectedNamespaces: ["kube-system"],
    contextAllowlist: [],
    allowDelete: true,
    allowApply: true,
    allowExec: true,
    dryRun: false,
    auditLog: false,
    requireHumanApproval,
  },
});

type Answer = { action: "accept" | "decline"; content?: Record<string, unknown> };

/** Connect an in-memory MCP client (optionally able to answer elicitation) to a freshly built server. */
async function connect(opts: { requireHuman?: boolean; answer?: (message: string) => Answer | Promise<Answer>; elicits?: boolean }) {
  const { server } = buildServer(config(opts.requireHuman));
  const prompts: string[] = [];
  const client = new Client({ name: "t", version: "0" }, { capabilities: opts.elicits === false ? {} : { elicitation: {} } });
  if (opts.elicits !== false) {
    client.setRequestHandler(ElicitRequestSchema, async (req) => {
      prompts.push(req.params.message);
      return (await opts.answer?.(req.params.message)) ?? { action: "accept", content: { confirm: true, typed: "shop" } };
    });
  }
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  return { client, prompts };
}

const text = (r: unknown) => ((r as { content: Array<{ text: string }> }).content[0]?.text ?? "");

const delPod = { apiVersion: "v1", kind: "Pod", name: "web-0", namespace: "shop" };
const delNs = { apiVersion: "v1", kind: "Namespace", name: "shop" };

afterEach(() => vi.restoreAllMocks());

describe("version tokens", () => {
  it("round-trips uid@resourceVersion and rejects incomplete objects", () => {
    expect(versionToken({ apiVersion: "v1", kind: "Pod", metadata: { uid: "u-1", resourceVersion: "42" } })).toBe("u-1@42");
    expect(versionToken({ apiVersion: "v1", kind: "Pod", metadata: { uid: "u-1" } })).toBeUndefined();
    expect(parseVersionToken("u-1@42")).toEqual({ uid: "u-1", resourceVersion: "42" });
    expect(parseVersionToken("garbage")).toBeUndefined();
    expect(parseVersionToken(undefined)).toBeUndefined();
  });
});

describe("delete_resource approval (end to end)", () => {
  it("shows the tool, full arguments, version and fingerprint, then deletes with the pinned token", async () => {
    vi.spyOn(K8sClient.prototype, "objectVersion").mockResolvedValue("u-1@100");
    const del = vi.spyOn(K8sClient.prototype, "deleteObject").mockResolvedValue({} as never);
    const { client, prompts } = await connect({});
    const res = await client.callTool({ name: "delete_resource", arguments: delPod });
    expect(text(res)).toContain('"deleted": true');
    expect(del).toHaveBeenCalledWith("v1", "Pod", "web-0", "shop", undefined, "u-1@100");
    expect(prompts[0]).toContain("tool: delete_resource");
    expect(prompts[0]).toContain('{"apiVersion":"v1","kind":"Pod","name":"web-0","namespace":"shop"}');
    expect(prompts[0]).toContain("resource version: u-1@100");
    expect(prompts[0]).toMatch(/fingerprint: [0-9a-f]{16}/);
  });

  it("does NOT delete when the object changed while the human was deciding", async () => {
    const versions = ["u-1@100", "u-1@101"];
    vi.spyOn(K8sClient.prototype, "objectVersion").mockImplementation(async () => versions.shift());
    const del = vi.spyOn(K8sClient.prototype, "deleteObject").mockResolvedValue({} as never);
    const { client } = await connect({});
    const res = await client.callTool({ name: "delete_resource", arguments: delPod });
    expect(text(res)).toContain("resource changed since the prompt");
    expect(del).not.toHaveBeenCalled();
  });

  it("does NOT delete when the object was recreated (new uid) while the human was deciding", async () => {
    const versions = ["u-1@100", "u-2@100"];
    vi.spyOn(K8sClient.prototype, "objectVersion").mockImplementation(async () => versions.shift());
    const del = vi.spyOn(K8sClient.prototype, "deleteObject").mockResolvedValue({} as never);
    const { client } = await connect({});
    const res = await client.callTool({ name: "delete_resource", arguments: delPod });
    expect(text(res)).toContain("resource changed since the prompt");
    expect(del).not.toHaveBeenCalled();
  });

  it("does NOT delete when the human declines", async () => {
    vi.spyOn(K8sClient.prototype, "objectVersion").mockResolvedValue("u-1@100");
    const del = vi.spyOn(K8sClient.prototype, "deleteObject").mockResolvedValue({} as never);
    const { client } = await connect({ answer: () => ({ action: "decline" }) });
    await client.callTool({ name: "delete_resource", arguments: delPod });
    expect(del).not.toHaveBeenCalled();
  });

  it("does not ask for a typed name for an ordinary delete", async () => {
    vi.spyOn(K8sClient.prototype, "objectVersion").mockResolvedValue("u-1@100");
    vi.spyOn(K8sClient.prototype, "deleteObject").mockResolvedValue({} as never);
    // Answers with the checkbox only: an ordinary delete must not require the typed field.
    const { client } = await connect({ answer: () => ({ action: "accept", content: { confirm: true } }) });
    const res = await client.callTool({ name: "delete_resource", arguments: delPod });
    expect(text(res)).toContain('"deleted": true');
  });
});

describe("namespace deletion requires the typed name", () => {
  it("deletes when the human types the namespace name", async () => {
    vi.spyOn(K8sClient.prototype, "objectVersion").mockResolvedValue("ns-1@7");
    const del = vi.spyOn(K8sClient.prototype, "deleteObject").mockResolvedValue({} as never);
    const { client, prompts } = await connect({});
    const res = await client.callTool({ name: "delete_resource", arguments: delNs });
    expect(text(res)).toContain('"deleted": true');
    expect(prompts[0]).toContain('delete namespace (and everything in it): "shop"');
    expect(del).toHaveBeenCalledWith("v1", "Namespace", "shop", undefined, undefined, "ns-1@7");
  });

  it("does NOT delete when the typed name does not match", async () => {
    vi.spyOn(K8sClient.prototype, "objectVersion").mockResolvedValue("ns-1@7");
    const del = vi.spyOn(K8sClient.prototype, "deleteObject").mockResolvedValue({} as never);
    const { client } = await connect({ answer: () => ({ action: "accept", content: { confirm: true, typed: "wrong" } }) });
    const res = await client.callTool({ name: "delete_resource", arguments: delNs });
    expect(text(res)).toContain("typed confirmation did not match");
    expect(del).not.toHaveBeenCalled();
  });

  it("does NOT delete when the namespace changed while the human was deciding", async () => {
    const versions = ["ns-1@7", "ns-1@8"];
    vi.spyOn(K8sClient.prototype, "objectVersion").mockImplementation(async () => versions.shift());
    const del = vi.spyOn(K8sClient.prototype, "deleteObject").mockResolvedValue({} as never);
    const { client } = await connect({});
    const res = await client.callTool({ name: "delete_resource", arguments: delNs });
    expect(text(res)).toContain("resource changed since the prompt");
    expect(del).not.toHaveBeenCalled();
  });
});

describe("K8S_REQUIRE_HUMAN_APPROVAL", () => {
  it("falls back to the flags when the client cannot elicit (default)", async () => {
    vi.spyOn(K8sClient.prototype, "objectVersion").mockResolvedValue("u-1@100");
    const del = vi.spyOn(K8sClient.prototype, "deleteObject").mockResolvedValue({} as never);
    const { client } = await connect({ elicits: false });
    await client.callTool({ name: "delete_resource", arguments: delPod });
    expect(del).toHaveBeenCalledWith("v1", "Pod", "web-0", "shop", undefined, "u-1@100");
  });

  it("refuses to delete when the client cannot elicit and human approval is required", async () => {
    vi.spyOn(K8sClient.prototype, "objectVersion").mockResolvedValue("u-1@100");
    const del = vi.spyOn(K8sClient.prototype, "deleteObject").mockResolvedValue({} as never);
    const { client, prompts } = await connect({ elicits: false, requireHuman: true });
    const res = await client.callTool({ name: "delete_resource", arguments: delPod });
    expect(text(res)).toContain("no human approval channel");
    expect(del).not.toHaveBeenCalled();
    expect(prompts).toHaveLength(0);
  });

  it("refuses exec_in_pod when the client cannot elicit and human approval is required", async () => {
    vi.spyOn(K8sClient.prototype, "podVersion").mockResolvedValue("p-1@5");
    const exec = vi.spyOn(K8sClient.prototype, "execInPod").mockResolvedValue({ stdout: "", stderr: "", exitCode: 0 });
    const { client } = await connect({ elicits: false, requireHuman: true });
    const res = await client.callTool({
      name: "exec_in_pod",
      arguments: { name: "web-0", namespace: "shop", container: "app", command: ["id"] },
    });
    expect(text(res)).toContain("no human approval channel");
    expect(exec).not.toHaveBeenCalled();
  });
});

describe("exec_in_pod approval (end to end)", () => {
  const execArgs = { name: "web-0", namespace: "shop", container: "app", command: ["sh", "-c", "id"] };

  it("shows the exact command and pod version, then execs", async () => {
    vi.spyOn(K8sClient.prototype, "podVersion").mockResolvedValue("p-1@5");
    const exec = vi.spyOn(K8sClient.prototype, "execInPod").mockResolvedValue({ stdout: "uid=0", stderr: "", exitCode: 0 });
    const { client, prompts } = await connect({});
    const res = await client.callTool({ name: "exec_in_pod", arguments: execArgs });
    expect(text(res)).toContain("uid=0");
    expect(exec).toHaveBeenCalledTimes(1);
    expect(prompts[0]).toContain("tool: exec_in_pod");
    expect(prompts[0]).toContain('"command":["sh","-c","id"]');
    expect(prompts[0]).toContain("resource version: p-1@5");
    expect(prompts[0]).toMatch(/fingerprint: [0-9a-f]{16}/);
  });

  it("does NOT exec when the pod was replaced while the human was deciding", async () => {
    const versions = ["p-1@5", "p-2@1"];
    vi.spyOn(K8sClient.prototype, "podVersion").mockImplementation(async () => versions.shift());
    const exec = vi.spyOn(K8sClient.prototype, "execInPod").mockResolvedValue({ stdout: "", stderr: "", exitCode: 0 });
    const { client } = await connect({});
    const res = await client.callTool({ name: "exec_in_pod", arguments: execArgs });
    expect(text(res)).toContain("resource changed since the prompt");
    expect(exec).not.toHaveBeenCalled();
  });
});

describe("other bound approvals", () => {
  const manifest = { apiVersion: "v1", kind: "ConfigMap", metadata: { name: "cfg", namespace: "shop" }, data: { a: "1" } };

  it("apply_manifest refuses when the live object changed during the prompt", async () => {
    const versions = ["c-1@10", "c-1@11"];
    vi.spyOn(K8sClient.prototype, "objectVersion").mockImplementation(async () => versions.shift());
    const apply = vi.spyOn(K8sClient.prototype, "applyObject").mockResolvedValue({ action: "replaced" });
    const { client } = await connect({});
    const res = await client.callTool({ name: "apply_manifest", arguments: { manifest } });
    expect(text(res)).toContain("resource changed since the prompt");
    expect(apply).not.toHaveBeenCalled();
  });

  it("apply_manifest passes the approved version to the write", async () => {
    vi.spyOn(K8sClient.prototype, "objectVersion").mockResolvedValue("c-1@10");
    const apply = vi.spyOn(K8sClient.prototype, "applyObject").mockResolvedValue({ action: "replaced" });
    const { client } = await connect({});
    await client.callTool({ name: "apply_manifest", arguments: { manifest } });
    expect(apply).toHaveBeenCalledWith(manifest, undefined, "c-1@10");
  });

  it("scale_deployment to 0 refuses when the deployment changed during the prompt", async () => {
    const versions = ["d-1@3", "d-1@4"];
    vi.spyOn(K8sClient.prototype, "deploymentVersion").mockImplementation(async () => versions.shift());
    const scale = vi.spyOn(K8sClient.prototype, "scaleDeployment").mockResolvedValue({} as never);
    const { client } = await connect({});
    const res = await client.callTool({ name: "scale_deployment", arguments: { name: "web", namespace: "shop", replicas: 0 } });
    expect(text(res)).toContain("resource changed since the prompt");
    expect(scale).not.toHaveBeenCalled();
  });
});

describe("K8sClient native concurrency", () => {
  it("sends the approved uid + resourceVersion as delete preconditions", async () => {
    const del = vi.spyOn(KubernetesObjectApi.prototype, "delete").mockResolvedValue({} as never);
    await new K8sClient({ inCluster: false }).deleteObject("v1", "Pod", "web-0", "shop", undefined, "u-1@100");
    expect(del.mock.calls[0]?.[6]).toEqual({ preconditions: { uid: "u-1", resourceVersion: "100" } });
  });

  it("sends no preconditions when the approval was not bound to a version", async () => {
    const del = vi.spyOn(KubernetesObjectApi.prototype, "delete").mockResolvedValue({} as never);
    await new K8sClient({ inCluster: false }).deleteObject("v1", "Pod", "web-0", "shop");
    expect(del.mock.calls[0]?.[6]).toBeUndefined();
  });

  it("objectVersion is uid@resourceVersion, undefined on 404, and throws on other errors", async () => {
    const read = vi.spyOn(KubernetesObjectApi.prototype, "read");
    const c = new K8sClient({ inCluster: false });
    read.mockResolvedValueOnce({ metadata: { uid: "u-9", resourceVersion: "3" } } as never);
    expect(await c.objectVersion("v1", "Pod", "p", "ns")).toBe("u-9@3");
    read.mockRejectedValueOnce(new ApiException(404, "not found", {}, {}));
    expect(await c.objectVersion("v1", "Pod", "p", "ns")).toBeUndefined();
    read.mockRejectedValueOnce(new ApiException(403, "forbidden", {}, {}));
    await expect(c.objectVersion("v1", "Pod", "p", "ns")).rejects.toBeInstanceOf(ApiException);
  });

  it("applyObject refuses to replace an object that no longer matches the approved version", async () => {
    vi.spyOn(KubernetesObjectApi.prototype, "read").mockResolvedValue({ metadata: { uid: "u-1", resourceVersion: "11" } } as never);
    const replace = vi.spyOn(KubernetesObjectApi.prototype, "replace").mockResolvedValue({} as never);
    const obj = { apiVersion: "v1", kind: "ConfigMap", metadata: { name: "cfg", namespace: "ns" } };
    await expect(new K8sClient({ inCluster: false }).applyObject(obj, undefined, "u-1@10")).rejects.toThrow(/changed since it was approved/);
    expect(replace).not.toHaveBeenCalled();
  });

  it("applyObject replaces with the freshly read resourceVersion when the approved version still matches", async () => {
    vi.spyOn(KubernetesObjectApi.prototype, "read").mockResolvedValue({ metadata: { uid: "u-1", resourceVersion: "10" } } as never);
    const replace = vi.spyOn(KubernetesObjectApi.prototype, "replace").mockResolvedValue({} as never);
    const obj = { apiVersion: "v1", kind: "ConfigMap", metadata: { name: "cfg", namespace: "ns" } };
    expect(await new K8sClient({ inCluster: false }).applyObject(obj, undefined, "u-1@10")).toEqual({ action: "replaced" });
    expect((replace.mock.calls[0]?.[0] as { metadata: { resourceVersion: string } }).metadata.resourceVersion).toBe("10");
  });
});
