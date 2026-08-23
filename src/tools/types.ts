import type { ZodRawShape } from "zod";
import type { K8sClient } from "../k8s/client.js";
import type { Capability, SecurityPolicy } from "../security.js";

export interface ToolContext {
  client: K8sClient;
  policy: SecurityPolicy;
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
