import { z } from "zod";
import type { ToolDef } from "./types.js";
import { jsonResult, summarizePods } from "./types.js";

const contextArg = {
  context: z.string().optional().describe("kube-config context to target (defaults to current-context)"),
};

export const readTools: ToolDef[] = [
  {
    name: "list_contexts",
    capability: "read",
    config: {
      title: "List kube-config contexts",
      description: "List the contexts (clusters) available in the loaded kube-config.",
      inputSchema: {},
    },
    handler: async (_args, { client, policy }) => {
      policy.guard({ tool: "list_contexts", capability: "read" });
      const contexts = client
        .listContextNames()
        .filter((c) => policy.isContextAllowed(c.name));
      return jsonResult(contexts);
    },
  },
  {
    name: "list_namespaces",
    capability: "read",
    config: {
      title: "List namespaces",
      description: "List namespaces in the cluster. Namespaces outside the allowlist are filtered out.",
      inputSchema: { ...contextArg },
    },
    handler: async (args, { client, policy }) => {
      const context = args.context as string | undefined;
      policy.guard({ tool: "list_namespaces", capability: "read", context });
      const res = await client.listNamespaces(context);
      const namespaces = (res.items ?? [])
        .map((n) => ({
          name: n.metadata?.name,
          status: n.status?.phase,
          protected: n.metadata?.name ? policy.isNamespaceProtected(n.metadata.name) : false,
        }))
        .filter((n) => n.name && policy.isNamespaceAllowed(n.name));
      return jsonResult(namespaces);
    },
  },
  {
    name: "list_pods",
    capability: "read",
    config: {
      title: "List pods",
      description: "List pods in a namespace with status, readiness, restarts, and node.",
      inputSchema: { namespace: z.string().describe("Namespace"), ...contextArg },
    },
    handler: async (args, { client, policy }) => {
      const namespace = args.namespace as string;
      const context = args.context as string | undefined;
      policy.guard({ tool: "list_pods", capability: "read", namespace, context });
      const res = await client.listPods(namespace, context);
      return jsonResult(summarizePods(res));
    },
  },
  {
    name: "get_pod",
    capability: "read",
    config: {
      title: "Get pod",
      description: "Fetch the full representation of a single pod.",
      inputSchema: {
        name: z.string().describe("Pod name"),
        namespace: z.string().describe("Namespace"),
        ...contextArg,
      },
    },
    handler: async (args, { client, policy }) => {
      const namespace = args.namespace as string;
      const context = args.context as string | undefined;
      policy.guard({ tool: "get_pod", capability: "read", namespace, context });
      const res = await client.getPod(args.name as string, namespace, context);
      return jsonResult(res);
    },
  },
  {
    name: "get_pod_logs",
    capability: "read",
    config: {
      title: "Get pod logs",
      description: "Fetch recent logs from a pod container.",
      inputSchema: {
        name: z.string().describe("Pod name"),
        namespace: z.string().describe("Namespace"),
        container: z.string().optional().describe("Container name (defaults to first container)"),
        tailLines: z.number().int().min(1).max(5000).optional().describe("Lines from the end (default 200)"),
        previous: z.boolean().optional().describe("Fetch logs from the previous terminated container"),
        ...contextArg,
      },
    },
    handler: async (args, { client, policy }) => {
      const namespace = args.namespace as string;
      const context = args.context as string | undefined;
      policy.guard({ tool: "get_pod_logs", capability: "read", namespace, context });
      const logs = await client.getPodLogs(
        args.name as string,
        namespace,
        {
          container: args.container as string | undefined,
          tailLines: (args.tailLines as number | undefined) ?? 200,
          previous: args.previous as boolean | undefined,
        },
        context,
      );
      return { content: [{ type: "text" as const, text: String(logs) || "(no output)" }] };
    },
  },
  {
    name: "list_deployments",
    capability: "read",
    config: {
      title: "List deployments",
      description: "List deployments in a namespace with replica status.",
      inputSchema: { namespace: z.string().describe("Namespace"), ...contextArg },
    },
    handler: async (args, { client, policy }) => {
      const namespace = args.namespace as string;
      const context = args.context as string | undefined;
      policy.guard({ tool: "list_deployments", capability: "read", namespace, context });
      const res = await client.listDeployments(namespace, context);
      const deployments = (res.items ?? []).map((d) => ({
        name: d.metadata?.name,
        namespace: d.metadata?.namespace,
        replicas: d.spec?.replicas,
        ready: d.status?.readyReplicas ?? 0,
        available: d.status?.availableReplicas ?? 0,
        images: (d.spec?.template?.spec?.containers ?? []).map((c) => `${c.name}=${c.image}`),
      }));
      return jsonResult(deployments);
    },
  },
  {
    name: "list_services",
    capability: "read",
    config: {
      title: "List services",
      description: "List services in a namespace with type and cluster IP.",
      inputSchema: { namespace: z.string().describe("Namespace"), ...contextArg },
    },
    handler: async (args, { client, policy }) => {
      const namespace = args.namespace as string;
      const context = args.context as string | undefined;
      policy.guard({ tool: "list_services", capability: "read", namespace, context });
      const res = await client.listServices(namespace, context);
      const services = (res.items ?? []).map((s) => ({
        name: s.metadata?.name,
        type: s.spec?.type,
        clusterIP: s.spec?.clusterIP,
        ports: (s.spec?.ports ?? []).map((p) => `${p.port}/${p.protocol}`),
      }));
      return jsonResult(services);
    },
  },
  {
    name: "list_nodes",
    capability: "read",
    config: {
      title: "List nodes",
      description: "List cluster nodes with readiness and kubelet version.",
      inputSchema: { ...contextArg },
    },
    handler: async (args, { client, policy }) => {
      const context = args.context as string | undefined;
      policy.guard({ tool: "list_nodes", capability: "read", context });
      const res = await client.listNodes(context);
      const nodes = (res.items ?? []).map((n) => ({
        name: n.metadata?.name,
        ready: (n.status?.conditions ?? []).find((c) => c.type === "Ready")?.status,
        version: n.status?.nodeInfo?.kubeletVersion,
        os: n.status?.nodeInfo?.osImage,
      }));
      return jsonResult(nodes);
    },
  },
  {
    name: "list_events",
    capability: "read",
    config: {
      title: "List events",
      description: "List recent events in a namespace — useful for diagnosing failures.",
      inputSchema: { namespace: z.string().describe("Namespace"), ...contextArg },
    },
    handler: async (args, { client, policy }) => {
      const namespace = args.namespace as string;
      const context = args.context as string | undefined;
      policy.guard({ tool: "list_events", capability: "read", namespace, context });
      const res = await client.listEvents(namespace, context);
      const events = (res.items ?? []).map((e) => ({
        type: e.type,
        reason: e.reason,
        object: `${e.involvedObject?.kind}/${e.involvedObject?.name}`,
        message: e.message,
        count: e.count,
        lastSeen: e.lastTimestamp,
      }));
      return jsonResult(events);
    },
  },
  {
    name: "get_resource",
    capability: "read",
    config: {
      title: "Get any resource",
      description:
        "Read an arbitrary Kubernetes object by apiVersion/kind/name (e.g. apiVersion=apps/v1, kind=Deployment).",
      inputSchema: {
        apiVersion: z.string().describe("e.g. v1, apps/v1, networking.k8s.io/v1"),
        kind: z.string().describe("e.g. Pod, Deployment, Ingress"),
        name: z.string().describe("Resource name"),
        namespace: z.string().optional().describe("Namespace (omit for cluster-scoped resources)"),
        ...contextArg,
      },
    },
    handler: async (args, { client, policy }) => {
      const namespace = args.namespace as string | undefined;
      const context = args.context as string | undefined;
      policy.guard({ tool: "get_resource", capability: "read", namespace, context });
      const res = await client.getObject(
        args.apiVersion as string,
        args.kind as string,
        args.name as string,
        namespace,
        context,
      );
      return jsonResult(res);
    },
  },
];
