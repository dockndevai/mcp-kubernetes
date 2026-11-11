import { createHash } from "node:crypto";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { ErrorCode, McpError } from "@modelcontextprotocol/sdk/types.js";

/**
 * Human-in-the-loop confirmation for destructive operations, via MCP elicitation.
 *
 * When the connected client advertises the elicitation capability, a destructive tool
 * pauses and asks the **human** to approve the exact action — the model cannot approve
 * on the user's behalf, which is the whole point (a model can trivially echo a
 * confirmation string; it cannot check a box a human is shown).
 *
 * The approval is bound to the action it was shown for:
 *  - `forCall(tool, args)` attaches the tool name and the (secret-redacted) arguments to every
 *    prompt, together with a fingerprint (`sha256(tool + canonical args)`), and writes an
 *    approval receipt to the audit log.
 *  - `probe()` pins a version token for the target (etag, resourceVersion, updated_at …). It is
 *    read before the prompt and again after the human answers; if it moved, the action is refused.
 *  - A prompt the human never answered (timeout) is a refusal, never an approval.
 *
 * When the client does NOT support elicitation, the call falls back to the policy gate that
 * already permitted it (admin mode + the `*_ALLOW_DELETE` flag) — unless `requireHuman` is set,
 * in which case there is no fallback and the operation is refused.
 */
export interface ConfirmRequest {
  /** Short verb phrase naming the action, e.g. "delete dashboard". */
  action: string;
  /** The exact resource affected (uid, name, id …) — shown to the human. */
  target: string;
  /** Extra context lines shown under the prompt. */
  details?: Record<string, string | number | boolean | undefined>;
  /**
   * Returns the target's current version token (etag, resourceVersion, updated_at, a content hash …).
   * Read before the prompt and again after the human answers; a different value refuses the action.
   */
  probe?: () => Promise<string | undefined>;
  /** Also require the human to type the target name — for the highest-impact deletes. */
  typed?: boolean;
}

/** What was approved, and by whom — logged so an operator can prove the exact action. */
export interface ApprovalReceipt {
  tool?: string;
  fingerprint?: string;
  version?: string;
  approvedBy: "human" | "flag-only";
}

export type ConfirmOutcome =
  | { approved: true; interactive: boolean; receipt: ApprovalReceipt }
  | { approved: false; reason: string };

export interface Confirmer {
  /** Whether the connected client can prompt the human at all. */
  available(): boolean;
  /** Ask the human to approve a destructive action. */
  confirm(req: ConfirmRequest): Promise<ConfirmOutcome>;
  /** A confirmer bound to one tool call: prompts and receipts carry the tool name, arguments and fingerprint. */
  forCall(tool: string, args: Record<string, unknown>): Confirmer;
}

export interface ConfirmerOptions {
  /** Server name written into approval audit lines. */
  name?: string;
  /** No flag-only fallback: refuse when no human can approve (client lacks elicitation, or the prompt fails). */
  requireHuman?: boolean;
  /** Write an approval line to stderr per decision. Default true. */
  audit?: boolean;
  /** How long to wait for the human, in ms. Default 5 minutes (the SDK default of 60 s is too short to read a prompt). */
  approvalTimeoutMs?: number;
}

const SECRET_KEY = /pass(word|wd)?|secret|token|api[-_]?key|credential|authorization|private[-_]?key|bearer|cookie/i;
const MAX_DEPTH = 8;
const MAX_DISPLAY = 1500;
const DEFAULT_APPROVAL_TIMEOUT_MS = 5 * 60 * 1000;

/** Deterministic JSON: sorted keys, secret-looking keys redacted, bigint stringified. */
function stable(value: unknown, depth = 0): unknown {
  if (value === null || value === undefined) return value ?? null;
  if (typeof value === "bigint") return value.toString();
  if (typeof value !== "object") return value;
  if (depth >= MAX_DEPTH) return "[depth-limit]";
  if (Array.isArray(value)) return value.map((v) => stable(v, depth + 1));
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(value as Record<string, unknown>).sort()) {
    const v = (value as Record<string, unknown>)[k];
    if (v === undefined) continue;
    out[k] = SECRET_KEY.test(k) ? "[redacted]" : stable(v, depth + 1);
  }
  return out;
}

/** The arguments as shown to the human and hashed: secret values never appear in either. */
export function canonicalArgs(args: Record<string, unknown>): string {
  return JSON.stringify(stable(args));
}

/** `sha256(tool + canonical args)`, truncated to 16 hex chars — identifies the exact action. */
export function fingerprint(tool: string, args: Record<string, unknown>): string {
  return createHash("sha256").update(`${tool}\n${canonicalArgs(args)}`).digest("hex").slice(0, 16);
}

type ProbeResult = { ok: true; value: string | undefined } | { ok: false };

async function runProbe(probe: ConfirmRequest["probe"]): Promise<ProbeResult> {
  if (!probe) return { ok: true, value: undefined };
  try {
    return { ok: true, value: await probe() };
  } catch {
    return { ok: false };
  }
}

export function makeConfirmer(server: McpServer, options: ConfirmerOptions = {}): Confirmer {
  const canElicit = (): boolean => !!server.server.getClientCapabilities()?.elicitation;
  const audit = options.audit ?? true;
  const timeout = options.approvalTimeoutMs ?? DEFAULT_APPROVAL_TIMEOUT_MS;

  const log = (rec: Record<string, unknown>): void => {
    if (!audit) return;
    process.stderr.write(
      `${JSON.stringify({ ts: new Date().toISOString(), audit: "approval", server: options.name ?? null, ...rec })}\n`,
    );
  };

  function build(call?: { tool: string; args: Record<string, unknown> }): Confirmer {
    const fp = call ? fingerprint(call.tool, call.args) : undefined;

    async function confirm(req: ConfirmRequest): Promise<ConfirmOutcome> {
      const { action, target, details, probe, typed } = req;
      const base = { tool: call?.tool, fingerprint: fp, action, target };
      const refuse = (reason: string, extra: Record<string, unknown> = {}): ConfirmOutcome => {
        log({ ...base, outcome: "refused", reason, ...extra });
        return { approved: false, reason };
      };
      const approve = (interactive: boolean, version: string | undefined): ConfirmOutcome => {
        const receipt: ApprovalReceipt = {
          tool: call?.tool,
          fingerprint: fp,
          version,
          approvedBy: interactive ? "human" : "flag-only",
        };
        log({ ...base, outcome: "approved", approvedBy: receipt.approvedBy, version: version ?? null });
        return { approved: true, interactive, receipt };
      };

      const before = await runProbe(probe);
      const version = before.ok ? before.value : undefined;

      if (!canElicit()) {
        if (options.requireHuman) {
          return refuse("no human approval channel: the client does not support elicitation and human approval is required");
        }
        // The client can't ask the human; the *_ALLOW_DELETE flag was the gate.
        return approve(false, version);
      }

      const lines: string[] = [];
      if (call) lines.push(`  • tool: ${call.tool}`);
      if (call) {
        const shown = canonicalArgs(call.args);
        lines.push(`  • arguments: ${shown.length > MAX_DISPLAY ? `${shown.slice(0, MAX_DISPLAY)}… (+${shown.length - MAX_DISPLAY} chars)` : shown}`);
      }
      for (const [k, v] of Object.entries(details ?? {})) {
        if (v !== undefined && v !== "") lines.push(`  • ${k}: ${v}`);
      }
      if (probe) lines.push(`  • resource version: ${version ?? "unavailable"}`);
      if (fp) lines.push(`  • fingerprint: ${fp}`);

      const message =
        `Confirm ${action}: "${target}". This is destructive and cannot be undone.` +
        (lines.length ? `\n${lines.join("\n")}` : "");

      type Field = { type: "boolean"; title: string; description: string } | { type: "string"; title: string; description: string };
      const properties: Record<string, Field> = {
        confirm: {
          type: "boolean",
          title: `Proceed with ${action}?`,
          description: `Approve ${action} on "${target}". Leave unchecked to cancel.`,
        },
      };
      const required = ["confirm"];
      if (typed) {
        properties.typed = {
          type: "string",
          title: `Type "${target}" to confirm`,
          description: "Must match the target name exactly.",
        };
        required.push("typed");
      }

      let res: Awaited<ReturnType<typeof server.server.elicitInput>>;
      try {
        res = await server.server.elicitInput({ message, requestedSchema: { type: "object", properties, required } }, { timeout });
      } catch (err) {
        // A human who never answered has not approved anything.
        if (err instanceof McpError && err.code === ErrorCode.RequestTimeout) {
          return refuse("approval timed out — no human response");
        }
        if (options.requireHuman) return refuse("approval prompt failed and human approval is required");
        // Elicitation advertised but failed at runtime — policy already gated this op.
        return approve(false, version);
      }

      if (res.action !== "accept" || res.content?.confirm !== true) {
        const verb = res.action === "decline" ? "declined" : res.action === "cancel" ? "cancelled" : "not confirmed";
        return refuse(`${verb} by the user`);
      }
      if (typed && String(res.content?.typed ?? "").trim() !== target) {
        return refuse("typed confirmation did not match the target name");
      }

      // The human took time to answer: make sure the target is still the one they were shown.
      if (probe && before.ok) {
        const after = await runProbe(probe);
        if (!after.ok || after.value !== before.value) {
          return refuse(
            `resource changed since the prompt (version ${before.value ?? "none"} → ${after.ok ? (after.value ?? "none") : "unreadable"})`,
            { versionBefore: before.value ?? null },
          );
        }
      }
      return approve(true, version);
    }

    return {
      available: canElicit,
      confirm,
      forCall: (tool, args) => build({ tool, args }),
    };
  }

  return build();
}
