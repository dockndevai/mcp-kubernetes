import { afterEach, describe, expect, it, vi } from "vitest";
import { ErrorCode, McpError } from "@modelcontextprotocol/sdk/types.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { canonicalArgs, fingerprint, makeConfirmer } from "../src/elicit.js";

/** Build a stub McpServer exposing just the `.server` surface makeConfirmer uses. */
function stubServer(opts: {
  elicitation?: unknown;
  elicit?: (params: unknown, options?: unknown) => Promise<unknown>;
}): McpServer {
  return {
    server: {
      getClientCapabilities: () => (opts.elicitation === undefined ? {} : { elicitation: opts.elicitation }),
      elicitInput: opts.elicit ?? (async () => ({ action: "accept", content: { confirm: true } })),
    },
  } as unknown as McpServer;
}

const HUMAN = { form: {} };

afterEach(() => vi.restoreAllMocks());

describe("makeConfirmer", () => {
  it("falls back to flag-only approval when the client cannot elicit", async () => {
    const c = makeConfirmer(stubServer({ elicitation: undefined }), { audit: false });
    expect(c.available()).toBe(false);
    const out = await c.confirm({ action: "delete dashboard", target: "abc" });
    expect(out).toMatchObject({ approved: true, interactive: false, receipt: { approvedBy: "flag-only" } });
  });

  it("approves when the human accepts and checks the box", async () => {
    const elicit = vi.fn(async () => ({ action: "accept", content: { confirm: true } }));
    const c = makeConfirmer(stubServer({ elicitation: HUMAN, elicit }), { audit: false });
    expect(c.available()).toBe(true);
    const out = await c.confirm({ action: "delete folder", target: "f1", details: { dashboards: 3 } });
    expect(out).toMatchObject({ approved: true, interactive: true, receipt: { approvedBy: "human" } });
    expect(elicit).toHaveBeenCalledOnce();
    // the exact target and action reach the human
    const params = (elicit.mock.calls[0] as unknown[])[0] as { message: string };
    expect(params.message).toContain("f1");
    expect(params.message).toContain("delete folder");
  });

  it("does NOT approve when the human declines or cancels", async () => {
    for (const action of ["decline", "cancel"] as const) {
      const c = makeConfirmer(stubServer({ elicitation: HUMAN, elicit: async () => ({ action }) }), { audit: false });
      const out = await c.confirm({ action: "delete", target: "x" });
      expect(out.approved).toBe(false);
    }
  });

  it("does NOT approve when accepted but the box is left unchecked", async () => {
    const c = makeConfirmer(
      stubServer({ elicitation: HUMAN, elicit: async () => ({ action: "accept", content: { confirm: false } }) }),
      { audit: false },
    );
    const out = await c.confirm({ action: "delete", target: "x" });
    expect(out.approved).toBe(false);
  });

  it("falls back to flag-only approval when elicitation is advertised but throws at runtime", async () => {
    const c = makeConfirmer(
      stubServer({
        elicitation: HUMAN,
        elicit: async () => {
          throw new Error("client blew up");
        },
      }),
      { audit: false },
    );
    const out = await c.confirm({ action: "delete", target: "x" });
    expect(out).toMatchObject({ approved: true, interactive: false });
  });
});

describe("approval timeout", () => {
  it("REFUSES when the human never answers (regression: used to fail open to approved)", async () => {
    const c = makeConfirmer(
      stubServer({
        elicitation: HUMAN,
        elicit: async () => {
          throw new McpError(ErrorCode.RequestTimeout, "Request timed out");
        },
      }),
      { audit: false },
    );
    const out = await c.confirm({ action: "delete topic", target: "orders" });
    expect(out).toEqual({ approved: false, reason: "approval timed out — no human response" });
  });

  it("waits longer than the SDK's 60 s default, and the wait is configurable", async () => {
    const elicit = vi.fn(async () => ({ action: "accept", content: { confirm: true } }));
    await makeConfirmer(stubServer({ elicitation: HUMAN, elicit }), { audit: false }).confirm({ action: "a", target: "t" });
    expect((elicit.mock.calls[0] as unknown[])[1]).toEqual({ timeout: 300_000 });
    await makeConfirmer(stubServer({ elicitation: HUMAN, elicit }), { audit: false, approvalTimeoutMs: 1234 }).confirm({
      action: "a",
      target: "t",
    });
    expect((elicit.mock.calls[1] as unknown[])[1]).toEqual({ timeout: 1234 });
  });
});

describe("requireHuman (fail closed)", () => {
  it("refuses when the client cannot elicit", async () => {
    const c = makeConfirmer(stubServer({ elicitation: undefined }), { audit: false, requireHuman: true });
    const out = await c.confirm({ action: "delete", target: "x" });
    expect(out.approved).toBe(false);
  });

  it("refuses when the prompt fails at runtime", async () => {
    const c = makeConfirmer(
      stubServer({
        elicitation: HUMAN,
        elicit: async () => {
          throw new Error("boom");
        },
      }),
      { audit: false, requireHuman: true },
    );
    expect((await c.confirm({ action: "delete", target: "x" })).approved).toBe(false);
  });

  it("still approves when a human accepts", async () => {
    const c = makeConfirmer(stubServer({ elicitation: HUMAN }), { audit: false, requireHuman: true });
    expect((await c.confirm({ action: "delete", target: "x" })).approved).toBe(true);
  });
});

describe("binding to the exact action", () => {
  it("shows the tool, full arguments and a fingerprint to the human", async () => {
    const elicit = vi.fn(async () => ({ action: "accept", content: { confirm: true } }));
    const c = makeConfirmer(stubServer({ elicitation: HUMAN, elicit }), { audit: false }).forCall("delete_topic", {
      topic: "orders",
      force: true,
    });
    const out = await c.confirm({ action: "delete topic", target: "orders" });
    const message = ((elicit.mock.calls[0] as unknown[])[0] as { message: string }).message;
    expect(message).toContain("tool: delete_topic");
    expect(message).toContain('{"force":true,"topic":"orders"}');
    const fp = fingerprint("delete_topic", { topic: "orders", force: true });
    expect(message).toContain(`fingerprint: ${fp}`);
    expect(out).toMatchObject({ approved: true, receipt: { tool: "delete_topic", fingerprint: fp } });
  });

  it("fingerprints the same action identically regardless of key order, and different actions differently", () => {
    expect(fingerprint("t", { a: 1, b: 2 })).toBe(fingerprint("t", { b: 2, a: 1 }));
    expect(fingerprint("t", { a: 1 })).not.toBe(fingerprint("t", { a: 2 }));
    expect(fingerprint("t", { a: 1 })).not.toBe(fingerprint("u", { a: 1 }));
  });

  it("never shows or hashes secret values", async () => {
    expect(canonicalArgs({ user: "u", password: "hunter2", nested: { apiKey: "k", ok: 1 } })).toBe(
      '{"nested":{"apiKey":"[redacted]","ok":1},"password":"[redacted]","user":"u"}',
    );
    expect(fingerprint("t", { password: "a" })).toBe(fingerprint("t", { password: "b" }));
    const elicit = vi.fn(async () => ({ action: "accept", content: { confirm: true } }));
    const c = makeConfirmer(stubServer({ elicitation: HUMAN, elicit }), { audit: false }).forCall("reset", { password: "hunter2" });
    await c.confirm({ action: "reset", target: "u" });
    expect(JSON.stringify(elicit.mock.calls)).not.toContain("hunter2");
  });

  it("writes an approval receipt to the audit log (stderr), never stdout", async () => {
    const err = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const out = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const c = makeConfirmer(stubServer({ elicitation: HUMAN }), { name: "mcp-test" }).forCall("delete_x", { id: 7 });
    await c.confirm({ action: "delete x", target: "7" });
    const line = JSON.parse(String((err.mock.calls[0] as unknown[])[0]));
    expect(line).toMatchObject({ audit: "approval", server: "mcp-test", tool: "delete_x", outcome: "approved", approvedBy: "human" });
    expect(line.fingerprint).toBe(fingerprint("delete_x", { id: 7 }));
    expect(out).not.toHaveBeenCalled();
  });

  it("logs refusals too", async () => {
    const err = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const c = makeConfirmer(stubServer({ elicitation: HUMAN, elicit: async () => ({ action: "decline" }) }));
    await c.confirm({ action: "delete x", target: "7" });
    expect(JSON.parse(String((err.mock.calls[0] as unknown[])[0]))).toMatchObject({ outcome: "refused", reason: "declined by the user" });
  });
});

describe("binding to the resource version (probe)", () => {
  it("approves when the version is unchanged, and records it in the receipt", async () => {
    const probe = vi.fn(async () => "rv-41");
    const c = makeConfirmer(stubServer({ elicitation: HUMAN }), { audit: false });
    const out = await c.confirm({ action: "delete pod", target: "p", probe });
    expect(probe).toHaveBeenCalledTimes(2); // before the prompt, and again after the human answers
    expect(out).toMatchObject({ approved: true, receipt: { version: "rv-41" } });
  });

  it("shows the pinned version to the human", async () => {
    const elicit = vi.fn(async () => ({ action: "accept", content: { confirm: true } }));
    await makeConfirmer(stubServer({ elicitation: HUMAN, elicit }), { audit: false }).confirm({
      action: "delete pod",
      target: "p",
      probe: async () => "rv-41",
    });
    expect(((elicit.mock.calls[0] as unknown[])[0] as { message: string }).message).toContain("resource version: rv-41");
  });

  it("REFUSES when the resource changed while the human was deciding", async () => {
    const versions = ["rv-41", "rv-42"];
    const c = makeConfirmer(stubServer({ elicitation: HUMAN }), { audit: false });
    const out = await c.confirm({ action: "delete pod", target: "p", probe: async () => versions.shift() });
    expect(out).toEqual({ approved: false, reason: "resource changed since the prompt (version rv-41 → rv-42)" });
  });

  it("REFUSES when the resource can no longer be read after approval (deleted/recreated)", async () => {
    let n = 0;
    const out = await makeConfirmer(stubServer({ elicitation: HUMAN }), { audit: false }).confirm({
      action: "delete pod",
      target: "p",
      probe: async () => {
        if (n++ === 0) return "rv-41";
        throw new Error("404");
      },
    });
    expect(out.approved).toBe(false);
  });

  it("proceeds unbound (version unavailable) when the first probe fails", async () => {
    const out = await makeConfirmer(stubServer({ elicitation: HUMAN }), { audit: false }).confirm({
      action: "delete pod",
      target: "p",
      probe: async () => {
        throw new Error("no api");
      },
    });
    expect(out).toMatchObject({ approved: true });
  });

  it("does not re-probe (nor refuse) when the human declines", async () => {
    const probe = vi.fn(async () => "v");
    const out = await makeConfirmer(stubServer({ elicitation: HUMAN, elicit: async () => ({ action: "decline" }) }), {
      audit: false,
    }).confirm({ action: "a", target: "t", probe });
    expect(out.approved).toBe(false);
    expect(probe).toHaveBeenCalledTimes(1);
  });
});

describe("typed confirmation", () => {
  const typedServer = (typed: string) =>
    stubServer({ elicitation: HUMAN, elicit: async () => ({ action: "accept", content: { confirm: true, typed } }) });

  it("approves only when the typed text equals the target name", async () => {
    const ok = await makeConfirmer(typedServer("prod-db"), { audit: false }).confirm({ action: "drop", target: "prod-db", typed: true });
    expect(ok.approved).toBe(true);
    const bad = await makeConfirmer(typedServer("prod"), { audit: false }).confirm({ action: "drop", target: "prod-db", typed: true });
    expect(bad).toEqual({ approved: false, reason: "typed confirmation did not match the target name" });
  });

  it("asks for the typed field in the form", async () => {
    const elicit = vi.fn(async () => ({ action: "accept", content: { confirm: true, typed: "t" } }));
    await makeConfirmer(stubServer({ elicitation: HUMAN, elicit }), { audit: false }).confirm({ action: "drop", target: "t", typed: true });
    const schema = ((elicit.mock.calls[0] as unknown[])[0] as { requestedSchema: { required: string[] } }).requestedSchema;
    expect(schema.required).toEqual(["confirm", "typed"]);
  });

  it("does not require typing unless asked", async () => {
    const out = await makeConfirmer(stubServer({ elicitation: HUMAN }), { audit: false }).confirm({ action: "a", target: "t" });
    expect(out.approved).toBe(true);
  });
});

describe("the prompt is fully reviewable", () => {
  const bound = (elicit: ReturnType<typeof vi.fn>) =>
    makeConfirmer(stubServer({ elicitation: HUMAN, elicit }), { audit: false });
  const ok = () => vi.fn(async () => ({ action: "accept", content: { confirm: true } }));
  const messageOf = (elicit: ReturnType<typeof vi.fn>) => ((elicit.mock.calls[0] as unknown[])[0] as { message: string }).message;

  it("shows long arguments IN FULL, so a padded prefix cannot hide the tail", async () => {
    const sql = `/* ${"x".repeat(5000)} */ DROP TABLE prod.users`;
    const elicit = ok();
    await bound(elicit).forCall("execute", { sql }).confirm({ action: "run sql", target: "prod.users" });
    expect(messageOf(elicit)).toContain("DROP TABLE prod.users");
  });

  it("REFUSES an action whose arguments are too long to review, instead of approving a prefix", async () => {
    const elicit = ok();
    const out = await bound(elicit).forCall("execute", { sql: "x".repeat(20_000) }).confirm({ action: "run sql", target: "t" });
    expect(out.approved).toBe(false);
    expect(out.approved === false && out.reason).toMatch(/too long to review/);
    expect(elicit).not.toHaveBeenCalled();
  });

  it("summarises over-long args only when the tool says they are an unreadable payload", async () => {
    const elicit = ok();
    const out = await bound(elicit)
      .forCall("upload", { path: "a.bin", content: "A".repeat(20_000) })
      .confirm({ action: "upload", target: "a.bin", summarizeLargeArgs: true });
    expect(out.approved).toBe(true);
    expect(messageOf(elicit)).toContain("not shown; covered by the fingerprint");
    expect(messageOf(elicit).length).toBeLessThan(4000);
  });
});

describe("secret-key matching is anchored to words", () => {
  it("redacts real secrets in any casing/shape", () => {
    for (const k of ["password", "passwordHash", "accessToken", "x-api-key", "apiKey", "client_secret", "refresh_token", "privateKey", "Authorization", "passcode"]) {
      expect(canonicalArgs({ [k]: "v" }), k).toContain("[redacted]");
    }
  });
  it("does not hide ordinary arguments that merely contain a secret-looking substring", () => {
    for (const k of ["bypass", "bypass_cache", "compass", "tokenizer", "keyword", "passed", "passenger", "subject"]) {
      expect(canonicalArgs({ [k]: "v" }), k).not.toContain("[redacted]");
    }
  });
});
