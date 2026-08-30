import { ApiException } from "@kubernetes/client-node";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { AppConfig } from "./config.js";
import { K8sClient } from "./k8s/client.js";
import { PolicyError, SecurityPolicy } from "./security.js";
import { adminTools } from "./tools/admin.js";
import { readTools } from "./tools/read.js";
import { annotationsFor } from "./tools/annotations.js";
import type { ToolContext, ToolDef } from "./tools/types.js";
import { writeTools } from "./tools/write.js";

export const ALL_TOOLS: ToolDef[] = [...readTools, ...writeTools, ...adminTools];

export function buildServer(config: AppConfig): { server: McpServer; enabled: string[] } {
  const policy = new SecurityPolicy(config.security);
  const client = new K8sClient(config.connection);
  const ctx: ToolContext = { client, policy };

  const server = new McpServer({ name: "mcp-kubernetes", version: "0.1.2" });

  const enabled: string[] = [];
  for (const tool of ALL_TOOLS) {
    if (!policy.isCapabilityEnabled(tool.capability)) continue;
    // Extra per-tool gate (e.g. exec_in_pod needs the exec opt-in on top of admin mode).
    if (tool.enabledWhen && !tool.enabledWhen(policy)) continue;
    enabled.push(tool.name);

    server.registerTool(tool.name, { ...tool.config, annotations: annotationsFor(tool) }, async (args: Record<string, unknown>) => {
      try {
        return await tool.handler(args ?? {}, ctx);
      } catch (err) {
        return toErrorResult(err);
      }
    });
  }

  return { server, enabled };
}

function toErrorResult(err: unknown) {
  let message: string;
  if (err instanceof PolicyError) {
    message = `Policy denied: ${err.message}`;
  } else if (err instanceof ApiException) {
    message = `Kubernetes API error (${err.code}): ${truncate(String(err.body ?? err.message))}`;
  } else if (err instanceof Error) {
    message = err.message;
  } else {
    message = String(err);
  }
  return { content: [{ type: "text" as const, text: message }], isError: true };
}

function truncate(s: string, max = 800): string {
  return s.length > max ? `${s.slice(0, max)}…` : s;
}
