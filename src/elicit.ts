import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

/**
 * Human-in-the-loop confirmation for destructive operations, via MCP elicitation.
 *
 * When the connected client advertises the elicitation capability, a destructive tool
 * pauses and asks the **human** to approve the exact action — the model cannot approve
 * on the user's behalf, which is the whole point (a model can trivially echo a
 * confirmation string; it cannot check a box a human is shown).
 *
 * When the client does NOT support elicitation, or the elicitation round-trip fails,
 * the call falls back to the policy gate that already permitted it (admin mode + the
 * `*_ALLOW_DELETE` flag). So enabling this is never *more* permissive than before — it
 * only adds a human checkpoint where one is possible.
 */
export interface ConfirmRequest {
  /** Short verb phrase naming the action, e.g. "delete dashboard". */
  action: string;
  /** The exact resource affected (uid, name, id …) — shown to the human. */
  target: string;
  /** Extra context lines shown under the prompt. */
  details?: Record<string, string | number | boolean | undefined>;
}

export type ConfirmOutcome =
  | { approved: true; interactive: boolean }
  | { approved: false; reason: string };

export interface Confirmer {
  /** Whether the connected client can prompt the human at all. */
  available(): boolean;
  /** Ask the human to approve a destructive action. */
  confirm(req: ConfirmRequest): Promise<ConfirmOutcome>;
}

export function makeConfirmer(server: McpServer): Confirmer {
  const canElicit = (): boolean => !!server.server.getClientCapabilities()?.elicitation;

  return {
    available: canElicit,
    async confirm({ action, target, details }): Promise<ConfirmOutcome> {
      if (!canElicit()) {
        // The client can't ask the human; the *_ALLOW_DELETE flag was the gate.
        return { approved: true, interactive: false };
      }
      const detailLines = Object.entries(details ?? {})
        .filter(([, v]) => v !== undefined && v !== "")
        .map(([k, v]) => `  • ${k}: ${v}`)
        .join("\n");
      const message =
        `Confirm ${action}: "${target}". This is destructive and cannot be undone.` +
        (detailLines ? `\n${detailLines}` : "");
      try {
        const res = await server.server.elicitInput({
          message,
          requestedSchema: {
            type: "object",
            properties: {
              confirm: {
                type: "boolean",
                title: `Proceed with ${action}?`,
                description: `Approve ${action} on "${target}". Leave unchecked to cancel.`,
              },
            },
            required: ["confirm"],
          },
        });
        if (res.action === "accept" && res.content?.confirm === true) {
          return { approved: true, interactive: true };
        }
        const verb =
          res.action === "decline" ? "declined" : res.action === "cancel" ? "cancelled" : "not confirmed";
        return { approved: false, reason: `${verb} by the user` };
      } catch {
        // Elicitation advertised but failed at runtime — policy already gated this op.
        return { approved: true, interactive: false };
      }
    },
  };
}
