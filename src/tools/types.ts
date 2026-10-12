import type { ZodRawShape } from "zod";
import type { Confirmer } from "../elicit.js";
import type { GuardClient } from "../guard.js";
import type { K8sClient } from "../k8s/client.js";
import type { Capability, SecurityPolicy } from "../security.js";

export interface ToolContext {
  client: K8sClient;
  policy: SecurityPolicy;
  /** Human-in-the-loop confirmation for destructive ops (no-op fallback when the client can't elicit). */
  confirm: Confirmer;
  /** Optional AI risk gate (laya-guard). Off unless K8S_GUARD_MODE is set. */
  guard: GuardClient;
}

export interface ToolResult {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
  // Mirror the MCP SDK's open CallToolResult index signature.
  [key: string]: unknown;
}

export interface ToolDef<Shape extends ZodRawShape = ZodRawShape> {
  name: string;
  capability: Capability;
  /** Marks a mutating tool as destructive (data loss possible). Defaults to `capability === "admin"`. */
  destructive?: boolean;
  /** Overrides the idempotency hint. Defaults to `true` for read tools, `false` otherwise. */
  idempotent?: boolean;
  /** If set, the tool is only registered when this predicate passes. */
  enabledWhen?: (policy: SecurityPolicy) => boolean;
  config: {
    title: string;
    description: string;
    inputSchema: Shape;
  };
  handler: (args: Record<string, unknown>, ctx: ToolContext) => Promise<ToolResult>;
}

export function jsonResult(value: unknown): ToolResult {
  return { content: [{ type: "text", text: JSON.stringify(value, null, 2) }] };
}

export function textResult(text: string): ToolResult {
  return { content: [{ type: "text", text }] };
}

/** Kubernetes `kind` values whose `data`/`stringData` fields can carry credentials. */
const SECRET_KINDS = new Set(["secret", "secrets"]);

/**
 * Strip credential values out of a Secret object before it reaches the model, while
 * keeping key names visible (useful for "what keys does this secret have"). No-op for
 * any other kind. Applied to every generic resource read/list (`get_resource`,
 * `list_resources`) since those can fetch arbitrary kinds, including Secrets.
 */
export function redactIfSecret<T extends Record<string, unknown>>(kind: string, obj: T): T {
  if (!SECRET_KINDS.has(kind.toLowerCase())) return obj;
  const { data, stringData, ...rest } = obj as Record<string, unknown> & {
    data?: Record<string, unknown>;
    stringData?: Record<string, unknown>;
  };
  const redactKeys = (fields?: Record<string, unknown>) =>
    fields ? Object.fromEntries(Object.keys(fields).map((k) => [k, "***redacted***"])) : undefined;
  return {
    ...rest,
    ...(data !== undefined ? { data: redactKeys(data) } : {}),
    ...(stringData !== undefined ? { stringData: redactKeys(stringData) } : {}),
  } as T;
}

/** Trim large list responses to the essential, model-friendly fields. */
export function summarizePods(list: { items?: Array<Record<string, any>> }) {
  return (list.items ?? []).map((p) => ({
    name: p.metadata?.name,
    namespace: p.metadata?.namespace,
    phase: p.status?.phase,
    ready:
      (p.status?.containerStatuses ?? []).filter((c: any) => c.ready).length +
      "/" +
      (p.status?.containerStatuses ?? []).length,
    restarts: (p.status?.containerStatuses ?? []).reduce(
      (n: number, c: any) => n + (c.restartCount ?? 0),
      0,
    ),
    node: p.spec?.nodeName,
    startTime: p.status?.startTime,
  }));
}
