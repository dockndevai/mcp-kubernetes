/**
 * Client for the local `laya-guard` daemon — an AI risk gate for high-risk commands.
 *
 * This is defence in depth on top of the deterministic `SecurityPolicy`: it runs only AFTER the
 * static gates have already permitted an operation, and it can only make things *stricter* — add a
 * human confirmation, or block — never grant anything the static policy denied.
 *
 * Modes (K8S_GUARD_MODE):
 *   off      — disabled (default); no calls, no behaviour change.
 *   monitor  — assess and log what it *would* do, but never actually block/prompt.
 *   enforce  — act on the decision: block, or require a human confirmation.
 *
 * Fail-closed: if the daemon is unreachable/slow in enforce mode, a high-risk op falls back to
 * requiring confirmation (configurable) rather than silently proceeding.
 */
import type { Confirmer } from "./elicit.js";
import { PolicyError } from "./security.js";

export type GuardMode = "off" | "monitor" | "enforce";

export interface GuardConfig {
  mode: GuardMode;
  url: string;
  timeoutMs: number;
  /** In enforce mode, what to do when the daemon can't be reached: "confirm" (default) or "allow". */
  failClosed: "confirm" | "allow";
}

export interface GuardDecision {
  decision: "allow" | "confirm" | "block";
  risk: string;
  confidence: number;
  reasons: string[];
  deterministic: boolean;
  model_available: boolean;
}

function boolMode(v: string | undefined): GuardMode {
  const m = (v ?? "off").trim().toLowerCase();
  return m === "monitor" || m === "enforce" ? m : "off";
}

export function loadGuardConfig(): GuardConfig {
  return {
    mode: boolMode(process.env.K8S_GUARD_MODE),
    url: (process.env.K8S_GUARD_URL || "http://127.0.0.1:8799").replace(/\/$/, ""),
    timeoutMs: Number(process.env.K8S_GUARD_TIMEOUT_MS ?? 2000),
    failClosed: (process.env.K8S_GUARD_FAIL_CLOSED ?? "confirm").toLowerCase() === "allow" ? "allow" : "confirm",
  };
}

export class GuardClient {
  constructor(private readonly config: GuardConfig) {}

  get enabled(): boolean {
    return this.config.mode !== "off";
  }

  private async assess(tool: string, command: string, context?: string): Promise<GuardDecision | null> {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.config.timeoutMs);
    try {
      const res = await fetch(`${this.config.url}/evaluate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tool, command, context }),
        signal: ctrl.signal,
      });
      if (!res.ok) return null;
      return (await res.json()) as GuardDecision;
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Assess a high-risk op and enforce the result per mode. Throws PolicyError to block/cancel.
   * Returns quietly when the op may proceed.
   */
  async enforce(
    ctx: { tool: string; command: string; context?: string },
    confirm: Confirmer,
  ): Promise<void> {
    if (this.config.mode === "off") return;

    const decision = await this.assess(ctx.tool, ctx.command, ctx.context);

    // Daemon unreachable.
    if (!decision) {
      if (this.config.mode === "monitor") {
        this.log(`unavailable — would allow (monitor)`, ctx);
        return;
      }
      if (this.config.failClosed === "allow") return;
      const ok = await confirm.confirm({
        action: "run a high-risk operation (laya-guard unavailable)",
        target: ctx.command,
      });
      if (!ok.approved) throw new PolicyError(`Blocked — laya-guard unavailable and not confirmed (${ok.reason}).`);
      return;
    }

    const summary = `${decision.decision} [${decision.risk}] ${decision.reasons.join("; ")}`;

    if (this.config.mode === "monitor") {
      this.log(`would ${summary}`, ctx);
      return;
    }

    // enforce
    if (decision.decision === "block") {
      this.log(`BLOCK ${summary}`, ctx);
      throw new PolicyError(`Blocked by laya-guard (risk: ${decision.risk}). ${decision.reasons.join("; ")}`);
    }
    if (decision.decision === "confirm") {
      const ok = await confirm.confirm({
        action: "run an operation laya-guard flagged as risky",
        target: ctx.command,
        details: { risk: decision.risk, reasons: decision.reasons.join("; ") },
      });
      if (!ok.approved) throw new PolicyError(`Cancelled — laya-guard flagged risk '${decision.risk}' (${ok.reason}).`);
    }
  }

  private log(msg: string, ctx: { tool: string; command: string }): void {
    process.stderr.write(
      `${JSON.stringify({ ts: new Date().toISOString(), guard: "laya-guard", mode: this.config.mode, tool: ctx.tool, note: msg, command: ctx.command.slice(0, 200) })}\n`,
    );
  }
}
