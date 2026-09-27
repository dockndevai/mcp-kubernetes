import { afterEach, describe, expect, it, vi } from "vitest";
import type { Confirmer } from "../src/elicit.js";
import { GuardClient, type GuardConfig, type GuardDecision } from "../src/guard.js";
import { PolicyError } from "../src/security.js";

const CFG = (mode: GuardConfig["mode"], failClosed: "confirm" | "allow" = "confirm"): GuardConfig => ({
  mode,
  url: "http://127.0.0.1:8799",
  timeoutMs: 500,
  failClosed,
});

const confirmer = (approve: boolean): Confirmer => ({
  available: () => true,
  confirm: async () => (approve ? { approved: true, interactive: true } : { approved: false, reason: "declined" }),
});

function stubDecision(d: Partial<GuardDecision>): void {
  vi.stubGlobal("fetch", async () => ({
    ok: true,
    json: async () => ({
      decision: "allow",
      risk: "none",
      confidence: 1,
      reasons: [],
      deterministic: false,
      model_available: true,
      ...d,
    }),
  }));
}

function stubDown(): void {
  vi.stubGlobal("fetch", async () => {
    throw new Error("connection refused");
  });
}

afterEach(() => vi.unstubAllGlobals());

const CTX = { tool: "exec_in_pod", command: "rm -rf /" };

describe("GuardClient modes", () => {
  it("off: never calls the daemon and never throws, even for a would-be block", async () => {
    const spy = vi.fn();
    vi.stubGlobal("fetch", spy);
    await new GuardClient(CFG("off")).enforce(CTX, confirmer(false));
    expect(spy).not.toHaveBeenCalled();
  });

  it("monitor: never throws even when the decision is block", async () => {
    stubDecision({ decision: "block", risk: "critical" });
    await expect(new GuardClient(CFG("monitor")).enforce(CTX, confirmer(false))).resolves.toBeUndefined();
  });

  it("enforce + block: throws PolicyError", async () => {
    stubDecision({ decision: "block", risk: "critical", reasons: ["matched block pattern"] });
    await expect(new GuardClient(CFG("enforce")).enforce(CTX, confirmer(true))).rejects.toBeInstanceOf(PolicyError);
  });

  it("enforce + confirm + approved: proceeds", async () => {
    stubDecision({ decision: "confirm", risk: "high" });
    await expect(new GuardClient(CFG("enforce")).enforce(CTX, confirmer(true))).resolves.toBeUndefined();
  });

  it("enforce + confirm + declined: throws", async () => {
    stubDecision({ decision: "confirm", risk: "high" });
    await expect(new GuardClient(CFG("enforce")).enforce(CTX, confirmer(false))).rejects.toBeInstanceOf(PolicyError);
  });

  it("enforce + allow: proceeds without prompting", async () => {
    stubDecision({ decision: "allow" });
    await expect(new GuardClient(CFG("enforce")).enforce(CTX, confirmer(false))).resolves.toBeUndefined();
  });
});

describe("fail-closed when the daemon is unreachable", () => {
  it("enforce + failClosed=confirm + declined: throws", async () => {
    stubDown();
    await expect(new GuardClient(CFG("enforce", "confirm")).enforce(CTX, confirmer(false))).rejects.toBeInstanceOf(
      PolicyError,
    );
  });

  it("enforce + failClosed=confirm + approved: proceeds", async () => {
    stubDown();
    await expect(new GuardClient(CFG("enforce", "confirm")).enforce(CTX, confirmer(true))).resolves.toBeUndefined();
  });

  it("enforce + failClosed=allow: proceeds", async () => {
    stubDown();
    await expect(new GuardClient(CFG("enforce", "allow")).enforce(CTX, confirmer(false))).resolves.toBeUndefined();
  });

  it("monitor: proceeds quietly when unreachable", async () => {
    stubDown();
    await expect(new GuardClient(CFG("monitor")).enforce(CTX, confirmer(false))).resolves.toBeUndefined();
  });
});
