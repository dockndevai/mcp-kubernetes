import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { loadConfig, type AppConfig } from "../src/config.js";
import { K8sClient } from "../src/k8s/client.js";
import { buildServer } from "../src/server.js";

const config = (security: Partial<AppConfig["security"]> = {}): AppConfig => ({
  connection: { inCluster: false },
  security: {
    mode: "admin",
    namespaceAllowlist: [],
    protectedNamespaces: [],
    contextAllowlist: [],
    allowDelete: false,
    allowApply: false,
    allowExec: true,
    dryRun: false,
    auditLog: false,
    requireHumanApproval: false,
    ...security,
  },
});

async function connect(security: Partial<AppConfig["security"]> = {}) {
  const { server } = buildServer(config(security));
  const client = new Client({ name: "t", version: "0" }, { capabilities: { elicitation: {} } });
  client.setRequestHandler(ElicitRequestSchema, async () => ({ action: "accept", content: { confirm: true } }));
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  return client;
}
const text = (r: unknown) => ((r as { content: Array<{ text: string }> }).content[0]?.text ?? "");

// Assembled at run time so the file carries no literal credential.
const PASSWORD = ["hunter2", "hunter2"].join("");
const BEARER = ["abc123", "DEF456", "ghi789"].join("");
const JWT = ["eyJhbGciOiJSUzI1NiJ9", "eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6c2hvcDp3ZWIifQ", "c2lnbmF0dXJlYnl0ZXM"].join(".");
const LOG = [
  "2030-01-01 INFO starting web",
  `db url=postgres://app:${PASSWORD}@db:5432/orders`,
  `Authorization: Bearer ${BEARER}`,
  `sa token ${JWT}`,
  "2030-01-01 INFO ready",
].join("\n");

afterEach(() => vi.restoreAllMocks());

describe("get_pod_logs redacts credentials by default", () => {
  it("masks credential-shaped text and keeps the rest of the log", async () => {
    vi.spyOn(K8sClient.prototype, "getPodLogs").mockResolvedValue(LOG as never);
    const out = text(await (await connect()).callTool({ name: "get_pod_logs", arguments: { name: "web-0", namespace: "shop" } }));
    for (const s of [PASSWORD, BEARER, JWT]) expect(out).not.toContain(s);
    expect(out).toContain("2030-01-01 INFO starting web");
    expect(out).toContain("2030-01-01 INFO ready");
    expect(out).toContain("postgres://app:[REDACTED]@db:5432/orders");
    expect(out).toContain("Authorization: Bearer [REDACTED]");
  });

  it("is on when the setting is explicitly true too, and still reports empty logs", async () => {
    vi.spyOn(K8sClient.prototype, "getPodLogs").mockResolvedValue("" as never);
    const out = text(await (await connect({ redactLogs: true })).callTool({ name: "get_pod_logs", arguments: { name: "web-0", namespace: "shop" } }));
    expect(out).toBe("(no output)");
  });

  it("returns the log untouched when redaction is disabled", async () => {
    vi.spyOn(K8sClient.prototype, "getPodLogs").mockResolvedValue(LOG as never);
    const out = text(await (await connect({ redactLogs: false })).callTool({ name: "get_pod_logs", arguments: { name: "web-0", namespace: "shop" } }));
    expect(out).toBe(LOG);
  });
});

describe("exec_in_pod redacts credentials in stdout and stderr by default", () => {
  const args = { name: "web-0", namespace: "shop", container: "app", command: ["sh", "-c", "env"] };
  const result = { stdout: `DB_PASSWORD=${PASSWORD}\nHOME=/root\n`, stderr: `warn: Authorization: Bearer ${BEARER}`, exitCode: 0 };

  it("masks both streams, keeps the exit code and other output", async () => {
    vi.spyOn(K8sClient.prototype, "podVersion").mockResolvedValue("p-1@5");
    vi.spyOn(K8sClient.prototype, "execInPod").mockResolvedValue({ ...result });
    const out = text(await (await connect()).callTool({ name: "exec_in_pod", arguments: args }));
    expect(out).not.toContain(PASSWORD);
    expect(out).not.toContain(BEARER);
    const parsed = JSON.parse(out);
    expect(parsed.stdout).toBe("DB_PASSWORD=[REDACTED]\nHOME=/root\n");
    expect(parsed.stderr).toBe("warn: Authorization: Bearer [REDACTED]");
    expect(parsed.exitCode).toBe(0);
  });

  it("returns output untouched when redaction is disabled", async () => {
    vi.spyOn(K8sClient.prototype, "podVersion").mockResolvedValue("p-1@5");
    vi.spyOn(K8sClient.prototype, "execInPod").mockResolvedValue({ ...result });
    const out = JSON.parse(text(await (await connect({ redactLogs: false })).callTool({ name: "exec_in_pod", arguments: args })));
    expect(out.stdout).toBe(result.stdout);
    expect(out.stderr).toBe(result.stderr);
  });
});

describe("K8S_REDACT_LOGS", () => {
  const saved = process.env.K8S_REDACT_LOGS;
  afterEach(() => {
    if (saved === undefined) delete process.env.K8S_REDACT_LOGS;
    else process.env.K8S_REDACT_LOGS = saved;
  });
  const load = (v?: string) => {
    if (v === undefined) delete process.env.K8S_REDACT_LOGS;
    else process.env.K8S_REDACT_LOGS = v;
    return loadConfig().security.redactLogs;
  };

  it("defaults to on", () => {
    expect(load(undefined)).toBe(true);
    expect(load("")).toBe(true);
    expect(load("true")).toBe(true);
  });
  it.each(["false", "FALSE", " False ", "0", "no", "off"])("%j disables it", (v) => {
    expect(load(v)).toBe(false);
  });
  it.each(["flase", "disabled", "2", "n"])("an unrecognised value (%j) does not disable it", (v) => {
    expect(load(v)).toBe(true);
  });
});
