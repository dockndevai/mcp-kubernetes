import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { AppConfig } from "../src/config.js";
import { K8sClient } from "../src/k8s/client.js";
import { redactSecret } from "../src/redact.js";
import { buildServer } from "../src/server.js";

const config: AppConfig = {
  connection: { inCluster: false },
  security: {
    mode: "read-only",
    namespaceAllowlist: [],
    protectedNamespaces: [],
    contextAllowlist: [],
    allowDelete: false,
    allowApply: false,
    allowExec: false,
    dryRun: false,
    auditLog: false,
    requireHumanApproval: false,
  },
};

async function connect() {
  const { server } = buildServer(config);
  const client = new Client({ name: "t", version: "0" }, { capabilities: {} });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  return client;
}
const text = (r: unknown) => ((r as { content: Array<{ text: string }> }).content[0]?.text ?? "");

const PASSWORD = "s3cr3t-p4ssw0rd";
const b64 = (s: string) => Buffer.from(s).toString("base64");
const secret = () => ({
  apiVersion: "v1",
  kind: "Secret",
  type: "Opaque",
  metadata: {
    name: "db",
    namespace: "shop",
    annotations: {
      "kubectl.kubernetes.io/last-applied-configuration": JSON.stringify({ kind: "Secret", data: { password: b64(PASSWORD) } }),
      "team": "payments",
    },
  },
  data: { password: b64(PASSWORD), user: b64("admin") },
  stringData: { token: PASSWORD },
});

afterEach(() => vi.restoreAllMocks());

describe("get_resource never returns Secret values", () => {
  it("redacts data, stringData and the last-applied-configuration annotation, but keeps keys and sizes", async () => {
    vi.spyOn(K8sClient.prototype, "effectiveNamespace").mockResolvedValue("shop");
    vi.spyOn(K8sClient.prototype, "getObject").mockResolvedValue(secret() as never);
    const out = text(await (await connect()).callTool({ name: "get_resource", arguments: { apiVersion: "v1", kind: "Secret", name: "db", namespace: "shop" } }));
    expect(out).not.toContain(PASSWORD);
    expect(out).not.toContain(b64(PASSWORD));
    expect(out).not.toContain(b64("admin"));
    const parsed = JSON.parse(out);
    expect(Object.keys(parsed.data)).toEqual(["password", "user"]);
    expect(parsed.data.password).toBe(`<redacted, ${PASSWORD.length} bytes>`);
    expect(parsed.stringData.token).toBe(`<redacted, ${PASSWORD.length} bytes>`);
    expect(parsed.metadata.annotations.team).toBe("payments");
    expect(parsed.metadata.annotations["kubectl.kubernetes.io/last-applied-configuration"]).toBe("<redacted>");
  });

  it("redacts by the requested kind even if the response omits `kind`", async () => {
    vi.spyOn(K8sClient.prototype, "getObject").mockResolvedValue({ data: { k: b64(PASSWORD) } } as never);
    const out = text(await (await connect()).callTool({ name: "get_resource", arguments: { apiVersion: "v1", kind: "Secret", name: "db", namespace: "shop" } }));
    expect(out).not.toContain(b64(PASSWORD));
  });

  it("leaves other kinds untouched", async () => {
    const cm = { apiVersion: "v1", kind: "ConfigMap", metadata: { name: "cfg" }, data: { color: "blue" } };
    vi.spyOn(K8sClient.prototype, "getObject").mockResolvedValue(cm as never);
    const out = text(await (await connect()).callTool({ name: "get_resource", arguments: { apiVersion: "v1", kind: "ConfigMap", name: "cfg", namespace: "shop" } }));
    expect(JSON.parse(out)).toEqual(cm);
  });
});

describe("redactSecret", () => {
  it("does not mutate its input and tolerates a Secret with no data", () => {
    const s = secret();
    const copy = JSON.parse(JSON.stringify(s));
    redactSecret(s);
    expect(s).toEqual(copy);
    expect(redactSecret({ apiVersion: "v1", kind: "Secret", metadata: { name: "empty" } })).toEqual({ apiVersion: "v1", kind: "Secret", metadata: { name: "empty" } });
  });

  it("redacts every item of a SecretList", () => {
    const out = JSON.stringify(redactSecret({ kind: "SecretList", items: [secret(), secret()] }));
    expect(out).not.toContain(b64(PASSWORD));
  });
});
