import { z } from "zod";
import type { KubernetesObject } from "@kubernetes/client-node";
import type { ToolDef } from "./types.js";
import { jsonResult, textResult } from "./types.js";

const contextArg = {
  context: z.string().optional().describe("kube-config context to target (defaults to current-context)"),
};

export const writeTools: ToolDef[] = [
  {
    name: "scale_deployment",
    capability: "write",
    config: {
      title: "Scale deployment",
      description: "Set the replica count of a deployment.",
      inputSchema: {
        name: z.string().describe("Deployment name"),
        namespace: z.string().describe("Namespace"),
        replicas: z.number().int().min(0).max(1000).describe("Desired replica count"),
        ...contextArg,
      },
    },
    handler: async (args, { client, policy }) => {
      const name = args.name as string;
      const namespace = args.namespace as string;
      const replicas = args.replicas as number;
      const context = args.context as string | undefined;
      const { dryRun } = policy.guard({ tool: "scale_deployment", capability: "write", namespace, context });
      if (dryRun) return textResult(`[dry-run] Would scale ${namespace}/${name} to ${replicas} replicas.`);
      await client.scaleDeployment(name, namespace, replicas, context);
      return jsonResult({ scaled: true, namespace, name, replicas });
    },
  },
  {
    name: "restart_deployment",
    capability: "write",
    config: {
      title: "Restart deployment",
      description: "Trigger a rolling restart of a deployment (equivalent to `kubectl rollout restart`).",
      inputSchema: {
        name: z.string().describe("Deployment name"),
        namespace: z.string().describe("Namespace"),
        ...contextArg,
      },
    },
    handler: async (args, { client, policy }) => {
      const name = args.name as string;
      const namespace = args.namespace as string;
      const context = args.context as string | undefined;
      const { dryRun } = policy.guard({ tool: "restart_deployment", capability: "write", namespace, context });
      if (dryRun) return textResult(`[dry-run] Would restart deployment ${namespace}/${name}.`);
      await client.restartDeployment(name, namespace, context);
      return jsonResult({ restarted: true, namespace, name });
    },
  },
  {
    name: "set_deployment_image",
    capability: "write",
    config: {
      title: "Set deployment image",
      description: "Update the image of a named container in a deployment.",
      inputSchema: {
        name: z.string().describe("Deployment name"),
        namespace: z.string().describe("Namespace"),
        container: z.string().describe("Container name within the pod template"),
        image: z.string().describe("New image reference, e.g. nginx:1.27"),
        ...contextArg,
      },
    },
    handler: async (args, { client, policy }) => {
      const name = args.name as string;
      const namespace = args.namespace as string;
      const container = args.container as string;
      const image = args.image as string;
      const context = args.context as string | undefined;
      const { dryRun } = policy.guard({
        tool: "set_deployment_image",
        capability: "write",
        namespace,
        context,
      });
      if (dryRun)
        return textResult(`[dry-run] Would set ${namespace}/${name} container '${container}' to ${image}.`);
      await client.setDeploymentImage(name, namespace, container, image, context);
      return jsonResult({ updated: true, namespace, name, container, image });
    },
  },
  {
    name: "create_namespace",
    capability: "write",
    config: {
      title: "Create namespace",
      description: "Create a new namespace.",
      inputSchema: { name: z.string().describe("Namespace name"), ...contextArg },
    },
    handler: async (args, { client, policy }) => {
      const name = args.name as string;
      const context = args.context as string | undefined;
      // The new namespace itself is the target, so scope-check it.
      const { dryRun } = policy.guard({
        tool: "create_namespace",
        capability: "write",
        namespace: name,
        context,
      });
      if (dryRun) return textResult(`[dry-run] Would create namespace '${name}'.`);
      await client.createNamespace(name, context);
      return jsonResult({ created: true, namespace: name });
    },
  },
  {
    name: "apply_manifest",
    capability: "write",
    enabledWhen: (p) => p.isCapabilityEnabled("write"),
    config: {
      title: "Apply a manifest",
      description:
        "Create or replace an arbitrary Kubernetes object from a manifest. Requires K8S_ALLOW_APPLY=true. " +
        "Pass the manifest as a JSON object with apiVersion, kind, metadata, and spec.",
      inputSchema: {
        manifest: z
          .record(z.any())
          .describe("The Kubernetes object as JSON (apiVersion, kind, metadata, spec, ...)"),
        ...contextArg,
      },
    },
    handler: async (args, { client, policy }) => {
      const manifest = args.manifest as KubernetesObject & { kind?: string };
      const namespace = manifest.metadata?.namespace;
      const context = args.context as string | undefined;
      const { dryRun } = policy.guard({
        tool: "apply_manifest",
        capability: "write",
        namespace,
        context,
        requiresApply: true,
      });
      if (!manifest.apiVersion || !manifest.kind || !manifest.metadata?.name) {
        return { content: [{ type: "text" as const, text: "Manifest must include apiVersion, kind, and metadata.name." }], isError: true };
      }
      if (dryRun)
        return textResult(
          `[dry-run] Would apply ${manifest.kind}/${manifest.metadata.name}` +
            `${namespace ? ` in ${namespace}` : ""}.`,
        );
      const { action } = await client.applyObject(manifest, context);
      return jsonResult({ applied: true, action, kind: manifest.kind, name: manifest.metadata.name, namespace });
    },
  },
];
