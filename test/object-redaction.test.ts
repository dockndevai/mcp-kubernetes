import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { ApiException } from "@kubernetes/client-node";
import { loadConfig, type AppConfig } from "../src/config.js";
import { K8sClient } from "../src/k8s/client.js";
import { isSecretName, redactObject } from "../src/redact.js";
import { buildServer } from "../src/server.js";

const config = (security: Partial<AppConfig["security"]> = {}): AppConfig => ({
  connection: { inCluster: false },
  security: {
    mode: "admin",
    namespaceAllowlist: [],
    protectedNamespaces: [],
    contextAllowlist: [],
    allowDelete: true,
    allowApply: true,
    allowExec: false,
    dryRun: false,
    auditLog: false,
    requireHumanApproval: false,
    ...security,
  },
});

async function connect(security: Partial<AppConfig["security"]> = {}) {
  const { server } = buildServer(config(security));
  const client = new Client({ name: "t", version: "0" }, { capabilities: { elicitation: {} } });
  client.setRequestHandler(ElicitRequestSchema, async () => ({ action: "accept", content: { confirm: true, name: "x" } }));
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  return client;
}
const text = (r: unknown) => ((r as { content: Array<{ text: string }> }).content[0]?.text ?? "");
const call = async (name: string, args: Record<string, unknown>, security: Partial<AppConfig["security"]> = {}) =>
  text(await (await connect(security)).callTool({ name, arguments: args }));

// Assembled at run time so the file carries no literal credential.
const j = (...p: string[]) => p.join("");
const PW = j("hunter2", "hunter2");
const TOKEN = j("tok-", "9f8e7d6c5b4a39281706");
const DB_URL_PW = j("p4ss", "w0rd-in-url");
const PEM_HEAD = j("-----BEGIN ", "RSA ", "PRIVATE KEY-----");
const PEM_FOOT = j("-----END ", "RSA ", "PRIVATE KEY-----");
const PEM_BODY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj";
const PEM = [PEM_HEAD, PEM_BODY, "MBGWRPZ0YyMgE0TtHn3kXKHk0YEFc5qS9eNsD4E7vUQ1o1pM8yq2lJf6tbAAA=", PEM_FOOT].join("\n");
const GH_TOKEN = j("gh", "p_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8");
const ARG_PW = j("cli-", "arg-secret-1");
const ARGS_KEY = j("cli-", "args-key-4");
const HDR_TOKEN = j("hdr-", "token-5a6b7c8d");
const GIT_PW = j("git-", "pass-6");
const HOOK_SECRET = j("hook-", "secret-7");
const FLAG_PW = j("cli-", "flag-secret-2");
const ENV_API = j("api-", "key-value-3");
const b64 = (s: string) => Buffer.from(s).toString("base64");

/** None of these may appear anywhere in tool output. */
const ALL_SECRETS = [PW, TOKEN, DB_URL_PW, PEM_BODY, GH_TOKEN, ARG_PW, FLAG_PW, ENV_API, b64(PW), ARGS_KEY, HDR_TOKEN, GIT_PW, HOOK_SECRET];
function clean(out: string) {
  for (const s of ALL_SECRETS) expect(out, `leaked: ${s}`).not.toContain(s);
}

const containers = () => [
  {
    name: "app",
    image: "shop/web:1",
    command: ["web", `--db-password=${ARG_PW}`, "--password", FLAG_PW, "--port", "8080"],
    args: ["--verbose", "--api-key", ARGS_KEY],
    livenessProbe: { httpGet: { path: "/healthz", port: 8080, httpHeaders: [{ name: "Authorization", value: `Bearer ${HDR_TOKEN}` }, { name: "X-Probe", value: "1" }] } },
    env: [
      { name: "DB_PASSWORD", value: PW },
      { name: "API_KEY", value: ENV_API },
      { name: "GITHUB_TOKEN", value: GH_TOKEN },
      { name: "SENTRY_DSN", value: "https://abc@o1.ingest.example.com/1" },
      { name: "DATABASE_URL", value: `postgres://app:${DB_URL_PW}@db:5432/orders` },
      { name: "MISC", value: `token=${TOKEN}` },
      { name: "REGION", value: "eu-west-1" },
      { name: "LOG_LEVEL", value: "info" },
      { name: "DB_USER", valueFrom: { secretKeyRef: { name: "db-creds", key: "user" } } },
      { name: "DB_PASSWORD_REF", valueFrom: { secretKeyRef: { name: "db-creds", key: "password" } } },
    ],
  },
];
const podSpec = () => ({
  containers: containers(),
  initContainers: [{ name: "init", image: "busybox", env: [{ name: "INIT_SECRET", value: PW }, { name: "MODE", value: "init" }] }],
});

/** What must be kept so the object stays useful for diagnosis. */
function expectEnvShape(out: string) {
  const o = out;
  expect(o).toContain("DB_PASSWORD");
  expect(o).toContain("eu-west-1");
  expect(o).toContain("LOG_LEVEL");
  expect(o).toContain("db-creds"); // secretKeyRef names stay visible
  expect(o).toContain("secretKeyRef");
  expect(o).toContain("INIT_SECRET");
  expect(o).toContain("shop/web:1");
  expect(o).toContain("--verbose");
  expect(o).toContain("--port");
  expect(o).toContain("X-Probe");
  expect(o).toContain("postgres://app:[REDACTED]@db:5432/orders"); // value kept, only the password masked
}

afterEach(() => vi.restoreAllMocks());

describe("get_pod redacts secret-shaped env values", () => {
  const pod = () => ({ apiVersion: "v1", kind: "Pod", metadata: { name: "web-0", namespace: "shop" }, spec: podSpec() });

  it("redacts env values (containers and initContainers) by name and by value shape, keeps the rest", async () => {
    vi.spyOn(K8sClient.prototype, "getPod").mockResolvedValue(pod() as never);
    const out = await call("get_pod", { name: "web-0", namespace: "shop" });
    clean(out);
    expectEnvShape(out);
    const p = JSON.parse(out);
    const env = Object.fromEntries(p.spec.containers[0].env.map((e: { name: string; value?: string }) => [e.name, e.value]));
    expect(env.DB_PASSWORD).toMatch(/^<redacted, \d+ bytes>$/);
    expect(env.SENTRY_DSN).toMatch(/^<redacted/);
    expect(env.REGION).toBe("eu-west-1");
    expect(env.LOG_LEVEL).toBe("info");
    expect(p.spec.containers[0].env.find((e: { name: string }) => e.name === "DB_USER").valueFrom.secretKeyRef.name).toBe("db-creds");
    const init = Object.fromEntries(p.spec.initContainers[0].env.map((e: { name: string; value: string }) => [e.name, e.value]));
    expect(init.INIT_SECRET).toMatch(/^<redacted/);
    expect(init.MODE).toBe("init");
  });

  it("works on the model-class instances the Kubernetes client returns (dates, prototypes)", async () => {
    class V1EnvVar { constructor(public name: string, public value?: string) {} }
    const p = { ...pod(), status: { startTime: new Date("2030-01-01T00:00:00Z") } };
    p.spec.containers[0].env = [new V1EnvVar("DB_PASSWORD", PW) as never, new V1EnvVar("REGION", "eu") as never];
    vi.spyOn(K8sClient.prototype, "getPod").mockResolvedValue(p as never);
    const out = await call("get_pod", { name: "web-0", namespace: "shop" });
    clean(out);
    expect(JSON.parse(out).status.startTime).toBe("2030-01-01T00:00:00.000Z");
  });

  it("is turned off by redactObjects=false, but not for Secrets", async () => {
    vi.spyOn(K8sClient.prototype, "getPod").mockResolvedValue(pod() as never);
    const out = await call("get_pod", { name: "web-0", namespace: "shop" }, { redactObjects: false });
    expect(out).toContain(PW);
    vi.spyOn(K8sClient.prototype, "effectiveNamespace").mockResolvedValue("shop");
    vi.spyOn(K8sClient.prototype, "getObject").mockResolvedValue({ apiVersion: "v1", kind: "Secret", metadata: { name: "s" }, data: { p: b64(PW) } } as never);
    const sec = await call("get_resource", { apiVersion: "v1", kind: "Secret", name: "s", namespace: "shop" }, { redactObjects: false });
    clean(sec);
  });
});

describe("get_resource redacts env in every workload kind (pod templates are recursed)", () => {
  const LAST = "kubectl.kubernetes.io/last-applied-configuration";
  const meta = () => ({
    name: "web",
    namespace: "shop",
    annotations: {
      [LAST]: JSON.stringify({ kind: "Deployment", spec: { template: { spec: { containers: containers() } } } }),
      team: "payments",
    },
  });
  const template = () => ({ spec: podSpec() });
  const cases: Array<[string, string, string, Record<string, unknown>]> = [
    ["Deployment", "apps/v1", "Deployment", { spec: { replicas: 2, template: template() } }],
    ["StatefulSet", "apps/v1", "StatefulSet", { spec: { template: template() } }],
    ["DaemonSet", "apps/v1", "DaemonSet", { spec: { template: template() } }],
    ["ReplicaSet", "apps/v1", "ReplicaSet", { spec: { template: template() } }],
    ["Job", "batch/v1", "Job", { spec: { template: template() } }],
    ["CronJob (jobTemplate)", "batch/v1", "CronJob", { spec: { schedule: "* * * * *", jobTemplate: { spec: { template: template() } } } }],
    ["a custom resource embedding a pod template", "example.com/v1", "Widget", { spec: { runtime: { podTemplate: { spec: podSpec() } } } }],
  ];
  it.each(cases)("%s", async (_n, apiVersion, kind, body) => {
    vi.spyOn(K8sClient.prototype, "effectiveNamespace").mockResolvedValue("shop");
    vi.spyOn(K8sClient.prototype, "getObject").mockResolvedValue({ apiVersion, kind, metadata: meta(), ...body } as never);
    const out = await call("get_resource", { apiVersion, kind, name: "web", namespace: "shop" });
    clean(out);
    expect(out).toContain("eu-west-1");
    expect(out).toContain("payments");
    expect(out).toContain("db-creds");
  });

  it("redacts the copy of the manifest inside the last-applied-configuration annotation", async () => {
    vi.spyOn(K8sClient.prototype, "effectiveNamespace").mockResolvedValue("shop");
    vi.spyOn(K8sClient.prototype, "getObject").mockResolvedValue({ apiVersion: "apps/v1", kind: "Deployment", metadata: meta(), spec: {} } as never);
    const out = await call("get_resource", { apiVersion: "apps/v1", kind: "Deployment", name: "web", namespace: "shop" });
    clean(out);
    const last = JSON.parse(JSON.parse(out).metadata.annotations[LAST]);
    expect(last.spec.template.spec.containers[0].env[0].name).toBe("DB_PASSWORD");
    expect(last.spec.template.spec.containers[0].env[0].value).toMatch(/^<redacted/);
  });

  it("replaces an annotation that is not JSON instead of guessing", () => {
    const out = redactObject({ kind: "Deployment", metadata: { annotations: { [LAST]: `not json ${PW}` } } }) as { metadata: { annotations: Record<string, string> } };
    expect(out.metadata.annotations[LAST]).toBe("<redacted>");
  });
});

describe("get_resource redacts ConfigMaps", () => {
  const cm = () => ({
    apiVersion: "v1",
    kind: "ConfigMap",
    metadata: { name: "app-config", namespace: "shop" },
    data: {
      "db.password": PW,
      "api_token": TOKEN,
      "credentials.json": `{"k":"${PW}"}`,
      "tls.key": PEM,
      "private.pem": PEM,
      "app.properties": `region=eu-west-1\nclient_secret=${PW}\nretries=3`,
      "notes.txt": `deploy key ${GH_TOKEN} was rotated`,
      "dsn.conf": `url=postgres://u:${DB_URL_PW}@h/db`,
      "feature-flags": "a=1\nb=2",
      LOG_LEVEL: "info",
    },
    binaryData: {
      "keystore.p12": b64(PW),
      "token": b64(PW),
      "blob.bin": b64(`password=${PW}\nother=1`),
      "logo.png": b64("PNGDATA"),
    },
  });

  it("masks secret-shaped keys, private keys, token shapes and key=value lines; keeps harmless entries", async () => {
    vi.spyOn(K8sClient.prototype, "effectiveNamespace").mockResolvedValue("shop");
    vi.spyOn(K8sClient.prototype, "getObject").mockResolvedValue(cm() as never);
    const out = await call("get_resource", { apiVersion: "v1", kind: "ConfigMap", name: "app-config", namespace: "shop" });
    clean(out);
    const c = JSON.parse(out);
    expect(c.data["db.password"]).toMatch(/^<redacted, \d+ bytes>$/);
    expect(c.data["tls.key"]).toMatch(/^<redacted/);
    expect(c.data["private.pem"]).not.toContain(PEM_BODY);
    expect(c.data["app.properties"]).toContain("region=eu-west-1");
    expect(c.data["app.properties"]).toContain("retries=3");
    expect(c.data["notes.txt"]).toContain("was rotated");
    expect(c.data["feature-flags"]).toBe("a=1\nb=2");
    expect(c.data.LOG_LEVEL).toBe("info");
    expect(c.binaryData["keystore.p12"]).toMatch(/^<redacted/);
    expect(c.binaryData.token).toMatch(/^<redacted/);
    expect(c.binaryData["blob.bin"]).toMatch(/^<redacted/);
    expect(c.binaryData["logo.png"]).toBe(b64("PNGDATA"));
  });

  it("also when the response omits `kind` (redacted by the requested kind)", async () => {
    vi.spyOn(K8sClient.prototype, "effectiveNamespace").mockResolvedValue("shop");
    const { kind: _k, ...noKind } = cm();
    vi.spyOn(K8sClient.prototype, "getObject").mockResolvedValue(noKind as never);
    const out = await call("get_resource", { apiVersion: "v1", kind: "ConfigMap", name: "app-config", namespace: "shop" });
    clean(out);
  });

  it("is returned untouched when redactObjects=false", async () => {
    vi.spyOn(K8sClient.prototype, "effectiveNamespace").mockResolvedValue("shop");
    vi.spyOn(K8sClient.prototype, "getObject").mockResolvedValue(cm() as never);
    const out = await call("get_resource", { apiVersion: "v1", kind: "ConfigMap", name: "app-config", namespace: "shop" }, { redactObjects: false });
    expect(out).toContain(PW);
  });
});

describe("get_resource redacts Route TLS private keys", () => {
  const route = (tls: Record<string, unknown>, top = false) => ({
    apiVersion: "route.openshift.io/v1",
    kind: "Route",
    metadata: { name: "web", namespace: "shop" },
    ...(top ? { tls } : { spec: { host: "web.example.com", tls } }),
  });
  it.each([[false], [true]])("tls.key (top-level=%s), and a private key pasted into another field", async (top) => {
    vi.spyOn(K8sClient.prototype, "effectiveNamespace").mockResolvedValue("shop");
    const tls = { termination: "edge", key: PEM, certificate: `-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n${PEM}`, caCertificate: "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----" };
    vi.spyOn(K8sClient.prototype, "getObject").mockResolvedValue(route(tls, top) as never);
    const out = await call("get_resource", { apiVersion: "route.openshift.io/v1", kind: "Route", name: "web", namespace: "shop" });
    clean(out);
    const t = top ? JSON.parse(out).tls : JSON.parse(out).spec.tls;
    expect(t.termination).toBe("edge");
    expect(t.key).toMatch(/^<redacted/);
    expect(t.certificate).toContain("BEGIN CERTIFICATE"); // public certificates stay readable
    expect(t.caCertificate).toContain("BBBB");
  });
});

describe("get_resource redacts other kinds that can carry credentials", () => {
  it("Event messages (kind Event)", async () => {
    vi.spyOn(K8sClient.prototype, "effectiveNamespace").mockResolvedValue("shop");
    vi.spyOn(K8sClient.prototype, "getObject").mockResolvedValue({ apiVersion: "v1", kind: "Event", metadata: { name: "e" }, message: `probe failed: password=${PW}`, reason: "Unhealthy" } as never);
    const out = await call("get_resource", { apiVersion: "v1", kind: "Event", name: "e", namespace: "shop" });
    clean(out);
    expect(out).toContain("probe failed");
  });

  it("BuildConfig webhook trigger secrets, and a password in a git URL", async () => {
    vi.spyOn(K8sClient.prototype, "effectiveNamespace").mockResolvedValue("shop");
    vi.spyOn(K8sClient.prototype, "getObject").mockResolvedValue({
      apiVersion: "build.openshift.io/v1",
      kind: "BuildConfig",
      metadata: { name: "web" },
      spec: {
        source: { git: { uri: `https://ci:${GIT_PW}@git.example.com/shop/web.git` } },
        triggers: [{ type: "GitHub", github: { secret: HOOK_SECRET } }, { type: "Generic", generic: { secret: HOOK_SECRET, allowEnv: true } }, { type: "ImageChange", imageChange: {} }],
      },
    } as never);
    const out = await call("get_resource", { apiVersion: "build.openshift.io/v1", kind: "BuildConfig", name: "web", namespace: "shop" });
    clean(out);
    expect(out).toContain("https://ci:[REDACTED]@git.example.com/shop/web.git");
    expect(out).toContain("allowEnv");
    expect(out).toContain("ImageChange");
  });
});

describe("list_events", () => {
  it("masks credentials in event messages", async () => {
    vi.spyOn(K8sClient.prototype, "listEvents").mockResolvedValue({
      items: [{ type: "Warning", reason: "Unhealthy", message: `Readiness probe failed: curl -H "Authorization: Bearer ${TOKEN}" password=${PW}`, involvedObject: { kind: "Pod", name: "web-0" } }],
    } as never);
    const out = await call("list_events", { namespace: "shop" });
    clean(out);
    expect(out).toContain("Readiness probe failed");
    const raw = await call("list_events", { namespace: "shop" }, { redactObjects: false });
    expect(raw).toContain(PW);
  });
});

describe("error responses from the API server", () => {
  it("are masked (the API server can echo submitted values in its error body)", async () => {
    vi.spyOn(K8sClient.prototype, "effectiveNamespace").mockResolvedValue("shop");
    vi.spyOn(K8sClient.prototype, "getObject").mockRejectedValue(new ApiException(422, "Unprocessable", `Invalid value: "password=${PW}"`, {}));
    const out = await call("get_resource", { apiVersion: "v1", kind: "ConfigMap", name: "x", namespace: "shop" });
    clean(out);
    expect(out).toContain("422");
  });
});

describe("write and admin tools never echo the object", () => {
  const manifest = () => ({ apiVersion: "apps/v1", kind: "Deployment", metadata: { name: "web", namespace: "shop" }, spec: { template: { spec: podSpec() } } });

  it("apply_manifest returns only the applied object's identity", async () => {
    vi.spyOn(K8sClient.prototype, "effectiveNamespace").mockResolvedValue("shop");
    vi.spyOn(K8sClient.prototype, "objectVersion").mockResolvedValue("u@1");
    vi.spyOn(K8sClient.prototype, "applyObject").mockResolvedValue({ action: "replaced" } as never);
    const out = await call("apply_manifest", { manifest: manifest() });
    clean(out);
    expect(JSON.parse(out)).toEqual({ applied: true, action: "replaced", kind: "Deployment", name: "web", namespace: "shop" });
    // dry-run
    const dry = await call("apply_manifest", { manifest: manifest() }, { dryRun: true });
    clean(dry);
  });

  it("delete_resource returns only {deleted, kind, name, namespace}", async () => {
    vi.spyOn(K8sClient.prototype, "effectiveNamespace").mockResolvedValue("shop");
    vi.spyOn(K8sClient.prototype, "objectVersion").mockResolvedValue("u@1");
    vi.spyOn(K8sClient.prototype, "deleteObject").mockResolvedValue(manifest() as never);
    const out = await call("delete_resource", { apiVersion: "apps/v1", kind: "Deployment", name: "web", namespace: "shop" });
    clean(out);
    expect(JSON.parse(out)).toEqual({ deleted: true, kind: "Deployment", name: "web", namespace: "shop" });
  });

  it("scale_deployment returns only {scaled, namespace, name, replicas}", async () => {
    vi.spyOn(K8sClient.prototype, "scaleDeployment").mockResolvedValue(manifest() as never);
    const out = await call("scale_deployment", { name: "web", namespace: "shop", replicas: 3 });
    clean(out);
    expect(JSON.parse(out)).toEqual({ scaled: true, namespace: "shop", name: "web", replicas: 3 });
  });

  it("list_deployments / list_pods return summaries without env", async () => {
    vi.spyOn(K8sClient.prototype, "listDeployments").mockResolvedValue({ items: [{ metadata: { name: "web" }, spec: { template: { spec: podSpec() } } }] } as never);
    vi.spyOn(K8sClient.prototype, "listPods").mockResolvedValue({ items: [{ metadata: { name: "web-0" }, spec: podSpec() }] } as never);
    clean(await call("list_deployments", { namespace: "shop" }));
    clean(await call("list_pods", { namespace: "shop" }));
  });
});

describe("redactObject", () => {
  it("does not mutate its input and is idempotent", () => {
    const pod = { kind: "Pod", spec: podSpec(), metadata: { name: "p" } };
    const copy = JSON.parse(JSON.stringify(pod));
    const once = redactObject(pod, "Pod");
    expect(pod).toEqual(copy);
    expect(redactObject(once, "Pod")).toEqual(once);
  });

  it("handles lists whose items omit kind, by the requested kind", () => {
    const list = { kind: "ConfigMapList", items: [{ metadata: { name: "a" }, data: { password: PW } }] };
    clean(JSON.stringify(redactObject(list, "ConfigMap")));
    clean(JSON.stringify(redactObject({ items: [{ metadata: { name: "a" }, data: { password: PW } }] }, "ConfigMap")));
  });

  it("redacts a Secret nested in another object (e.g. a Template or List) even with heuristics off", () => {
    const nested = { kind: "List", items: [{ kind: "Secret", metadata: { name: "s" }, data: { p: b64(PW) } }, { kind: "Template", objects: [{ kind: "Secret", stringData: { p: PW } }] }] };
    clean(JSON.stringify(redactObject(nested, undefined, false)));
  });

  it("with heuristics off leaves env alone", () => {
    expect(JSON.stringify(redactObject({ kind: "Pod", spec: podSpec() }, "Pod", false))).toContain(PW);
  });

  it("fails closed on absurdly deep nesting instead of recursing without bound", () => {
    let deep: Record<string, unknown> = { leaf: "x" };
    for (let i = 0; i < 200; i++) deep = { a: deep };
    expect(JSON.stringify(redactObject(deep))).toContain("nested too deep");
  });

  it("does not choke on primitives, null and very deep nesting", () => {
    expect(redactObject(null)).toBeNull();
    expect(redactObject("x")).toBe("x");
    let deep: Record<string, unknown> = { env: [{ name: "PASSWORD", value: PW }] };
    for (let i = 0; i < 200; i++) deep = { a: deep };
    clean(JSON.stringify(redactObject(deep)));
  });
});

describe("isSecretName", () => {
  it.each([
    "PASSWORD", "DB_PASSWORD", "db-password", "dbPassword", "DB_PASS", "SMTP_PWD", "SECRET", "JWT_SECRET", "CLIENT_SECRET", "SECRET_KEY_BASE",
    "TOKEN", "GITHUB_TOKEN", "API_KEY", "apiKey", "AWS_SECRET_ACCESS_KEY", "ENCRYPTION_KEY", "TLS_KEY", "CREDENTIALS", "GOOGLE_APPLICATION_CREDENTIALS", "BASIC_AUTH", "AUTH",
    "SENTRY_DSN", "DSN", "CONNECTION_STRING", "AZURE_STORAGE_CONNECTION_STRING", "JWT",
  ])("treats %s as secret-shaped", (n) => expect(isSecretName(n)).toBe(true));
  it.each([
    "REGION", "LOG_LEVEL", "DB_USER", "DB_HOST", "PORT", "SECRET_NAME", "TOKEN_COUNT", "TOKENIZER", "KEYBOARD", "PASSWORD_FILE", "BYPASS", "CLUSTER_NAME", "NODE_ENV",
  ])("leaves %s readable", (n) => expect(isSecretName(n)).toBe(false));
});

describe("K8S_REDACT_OBJECTS", () => {
  const save = process.env.K8S_REDACT_OBJECTS;
  afterEach(() => {
    if (save === undefined) delete process.env.K8S_REDACT_OBJECTS;
    else process.env.K8S_REDACT_OBJECTS = save;
  });
  it("is on by default and only an explicit false/0/no/off turns it off", () => {
    delete process.env.K8S_REDACT_OBJECTS;
    expect(loadConfig().security.redactObjects).toBe(true);
    for (const v of ["false", "0", "no", "off", " FALSE "]) {
      process.env.K8S_REDACT_OBJECTS = v;
      expect(loadConfig().security.redactObjects, v).toBe(false);
    }
    for (const v of ["true", "", "flase", "disabled"]) {
      process.env.K8S_REDACT_OBJECTS = v;
      expect(loadConfig().security.redactObjects, v).toBe(true);
    }
  });
});
