import { z } from "zod";
import type { ToolDef } from "./types.js";
import { jsonResult, textResult } from "./types.js";

const contextArg = {
  context: z.string().optional().describe("kube-config context to target (defaults to current-context)"),
};

/**
 * Admin tools are registered only in admin mode, and the two most dangerous
 * (delete, exec) have their own additional opt-in flags on top of that.
 */
export const adminTools: ToolDef[] = [
  {
    name: "delete_resource",
    capability: "admin",
    config: {
      title: "Delete a resource",
      description:
        "Delete an arbitrary Kubernetes object by apiVersion/kind/name. Requires admin mode AND " +
        "K8S_ALLOW_DELETE=true. Protected namespaces are refused. Irreversible.",
      inputSchema: {
        apiVersion: z.string().describe("e.g. v1, apps/v1"),
        kind: z.string().describe("e.g. Pod, Deployment"),
        name: z.string().describe("Resource name"),
        namespace: z.string().optional().describe("Namespace (omit for cluster-scoped resources)"),
        ...contextArg,
      },
    },
    handler: async (args, { client, policy }) => {
      const namespace = args.namespace as string | undefined;
      const context = args.context as string | undefined;
      const { dryRun } = policy.guard({
        tool: "delete_resource",
        capability: "admin",
        namespace,
        context,
        destructive: true,
      });
      const ref = `${args.kind}/${args.name}${namespace ? ` in ${namespace}` : ""}`;
      if (dryRun) return textResult(`[dry-run] Would delete ${ref}.`);
      await client.deleteObject(
        args.apiVersion as string,
        args.kind as string,
        args.name as string,
        namespace,
        context,
      );
      return jsonResult({ deleted: true, kind: args.kind, name: args.name, namespace });
    },
  },
  {
    name: "exec_in_pod",
    capability: "admin",
    // Only ever registered when admin mode AND the exec opt-in are both on.
    enabledWhen: (p) => p.execEnabled,
    config: {
      title: "Exec in pod",
      description:
        "Run a command inside a pod container and return its output. Requires admin mode AND " +
        "K8S_ALLOW_EXEC=true. This is powerful — treat with care.",
      inputSchema: {
        name: z.string().describe("Pod name"),
        namespace: z.string().describe("Namespace"),
        container: z.string().describe("Container name"),
        command: z.array(z.string()).min(1).describe("Command and args, e.g. [\"sh\",\"-c\",\"ls /\"]"),
        ...contextArg,
      },
    },
    handler: async (args, { client, policy }) => {
      const namespace = args.namespace as string;
      const context = args.context as string | undefined;
      const { dryRun } = policy.guard({
        tool: "exec_in_pod",
        capability: "admin",
        namespace,
        context,
        requiresExec: true,
      });
      const command = args.command as string[];
      if (dryRun)
        return textResult(
          `[dry-run] Would exec in ${namespace}/${args.name} [${args.container}]: ${command.join(" ")}`,
        );
      const result = await client.execInPod(
        args.name as string,
        namespace,
        args.container as string,
        command,
        context,
      );
      return jsonResult(result);
    },
  },
];
