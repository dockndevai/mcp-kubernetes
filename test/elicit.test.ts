import { describe, expect, it, vi } from "vitest";
import { makeConfirmer } from "../src/elicit.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

/** Build a stub McpServer exposing just the `.server` surface makeConfirmer uses. */
function stubServer(opts: {
  elicitation?: unknown;
  elicit?: (params: unknown) => Promise<unknown>;
}): McpServer {
  return {
    server: {
      getClientCapabilities: () => (opts.elicitation === undefined ? {} : { elicitation: opts.elicitation }),
      elicitInput: opts.elicit ?? (async () => ({ action: "accept", content: { confirm: true } })),
    },
  } as unknown as McpServer;
}

describe("makeConfirmer", () => {
  it("falls back to approved when the client cannot elicit", async () => {
    const c = makeConfirmer(stubServer({ elicitation: undefined }));
    expect(c.available()).toBe(false);
    const out = await c.confirm({ action: "delete dashboard", target: "abc" });
    expect(out).toEqual({ approved: true, interactive: false });
  });

  it("approves when the human accepts and checks the box", async () => {
    const elicit = vi.fn(async () => ({ action: "accept", content: { confirm: true } }));
    const c = makeConfirmer(stubServer({ elicitation: { form: {} }, elicit }));
    expect(c.available()).toBe(true);
    const out = await c.confirm({ action: "delete folder", target: "f1", details: { dashboards: 3 } });
    expect(out).toEqual({ approved: true, interactive: true });
    expect(elicit).toHaveBeenCalledOnce();
    // the exact target and action reach the human
    const params = elicit.mock.calls[0][0] as { message: string };
    expect(params.message).toContain("f1");
    expect(params.message).toContain("delete folder");
  });

  it("does NOT approve when the human declines or cancels", async () => {
    for (const action of ["decline", "cancel"] as const) {
      const c = makeConfirmer(stubServer({ elicitation: { form: {} }, elicit: async () => ({ action }) }));
      const out = await c.confirm({ action: "delete", target: "x" });
      expect(out.approved).toBe(false);
    }
  });

  it("does NOT approve when accepted but the box is left unchecked", async () => {
    const c = makeConfirmer(stubServer({ elicitation: { form: {} }, elicit: async () => ({ action: "accept", content: { confirm: false } }) }));
    const out = await c.confirm({ action: "delete", target: "x" });
    expect(out.approved).toBe(false);
  });

  it("falls back to approved when elicitation is advertised but throws at runtime", async () => {
    const c = makeConfirmer(
      stubServer({
        elicitation: { form: {} },
        elicit: async () => {
          throw new Error("client blew up");
        },
      }),
    );
    const out = await c.confirm({ action: "delete", target: "x" });
    expect(out).toEqual({ approved: true, interactive: false });
  });
});
