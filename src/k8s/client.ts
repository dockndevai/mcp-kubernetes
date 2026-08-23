/**
 * Thin wrapper over @kubernetes/client-node. Handles kube-config loading,
 * per-call context selection, and the handful of operations the tools need.
 */
import { PassThrough } from "node:stream";
import {
  AppsV1Api,
  CoreV1Api,
  Exec,
  KubeConfig,
  KubernetesObjectApi,
  type KubernetesObject,
} from "@kubernetes/client-node";

/** The subset of a KubernetesObject the object API needs to identify it. */
type ObjectHeader = { apiVersion: string; kind: string; metadata: { name: string; namespace?: string } };
import type { KubeConnection } from "../config.js";

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
}

export class K8sClient {
  private readonly base: KubeConfig;

  constructor(conn: KubeConnection) {
    this.base = new KubeConfig();
    if (conn.inCluster) {
      this.base.loadFromCluster();
    } else if (conn.kubeconfigPath) {
      this.base.loadFromFile(conn.kubeconfigPath);
    } else {
      this.base.loadFromDefault();
    }
    if (conn.defaultContext) {
      this.base.setCurrentContext(conn.defaultContext);
    }
  }

  /** Names of all contexts in the loaded kube-config. */
  listContextNames(): { name: string; cluster: string; current: boolean }[] {
    const current = this.base.getCurrentContext();
    return this.base.getContexts().map((c) => ({
      name: c.name,
      cluster: c.cluster,
      current: c.name === current,
    }));
  }

  currentContext(): string {
    return this.base.getCurrentContext();
  }

  /** Return a KubeConfig scoped to a specific context (or the default). */
  private scoped(context?: string): KubeConfig {
    if (!context) return this.base;
    const kc = new KubeConfig();
    kc.loadFromString(this.base.exportConfig());
    kc.setCurrentContext(context);
    return kc;
  }

  private core(context?: string): CoreV1Api {
    return this.scoped(context).makeApiClient(CoreV1Api);
  }

  private apps(context?: string): AppsV1Api {
    return this.scoped(context).makeApiClient(AppsV1Api);
  }

  private objects(context?: string): KubernetesObjectApi {
    return KubernetesObjectApi.makeApiClient(this.scoped(context));
  }

  // --- Reads -----------------------------------------------------------------

  listNamespaces(context?: string) {
    return this.core(context).listNamespace();
  }

  listPods(namespace: string, context?: string) {
    return this.core(context).listNamespacedPod({ namespace });
  }

  getPod(name: string, namespace: string, context?: string) {
    return this.core(context).readNamespacedPod({ name, namespace });
  }

  getPodLogs(
    name: string,
    namespace: string,
    opts: { container?: string; tailLines?: number; previous?: boolean },
    context?: string,
  ) {
    return this.core(context).readNamespacedPodLog({
      name,
      namespace,
      container: opts.container,
      tailLines: opts.tailLines,
      previous: opts.previous,
    });
  }

  listDeployments(namespace: string, context?: string) {
    return this.apps(context).listNamespacedDeployment({ namespace });
  }

  listServices(namespace: string, context?: string) {
    return this.core(context).listNamespacedService({ namespace });
  }

  listNodes(context?: string) {
    return this.core(context).listNode();
  }

  listEvents(namespace: string, context?: string) {
    return this.core(context).listNamespacedEvent({ namespace });
  }

  getObject(
    apiVersion: string,
    kind: string,
    name: string,
    namespace: string | undefined,
    context?: string,
  ) {
    return this.objects(context).read({ apiVersion, kind, metadata: { name, namespace } });
  }

  // --- Writes ----------------------------------------------------------------

  async scaleDeployment(name: string, namespace: string, replicas: number, context?: string) {
    const apps = this.apps(context);
    const dep = await apps.readNamespacedDeployment({ name, namespace });
    if (!dep.spec) throw new Error(`Deployment '${name}' has no spec.`);
    dep.spec.replicas = replicas;
    return apps.replaceNamespacedDeployment({ name, namespace, body: dep });
  }

  async restartDeployment(name: string, namespace: string, context?: string) {
    const apps = this.apps(context);
    const dep = await apps.readNamespacedDeployment({ name, namespace });
    if (!dep.spec) throw new Error(`Deployment '${name}' has no spec.`);
    dep.spec.template.metadata = dep.spec.template.metadata ?? {};
    dep.spec.template.metadata.annotations = {
      ...(dep.spec.template.metadata.annotations ?? {}),
      "kubectl.kubernetes.io/restartedAt": new Date().toISOString(),
    };
    return apps.replaceNamespacedDeployment({ name, namespace, body: dep });
  }

  async setDeploymentImage(
    name: string,
    namespace: string,
    container: string,
    image: string,
    context?: string,
  ) {
    const apps = this.apps(context);
    const dep = await apps.readNamespacedDeployment({ name, namespace });
    const containers = dep.spec?.template?.spec?.containers ?? [];
    const target = containers.find((c) => c.name === container);
    if (!target) {
      throw new Error(
        `Container '${container}' not found in deployment '${name}'. Containers: ${containers
          .map((c) => c.name)
          .join(", ")}`,
      );
    }
    target.image = image;
    return apps.replaceNamespacedDeployment({ name, namespace, body: dep });
  }

  createNamespace(name: string, context?: string) {
    return this.core(context).createNamespace({ body: { metadata: { name } } });
  }

  /** Create the object if absent, otherwise replace it (preserving resourceVersion). */
  async applyObject(obj: KubernetesObject, context?: string): Promise<{ action: "created" | "replaced" }> {
    const api = this.objects(context);
    try {
      const existing = await api.read(obj as ObjectHeader);
      const merged = {
        ...obj,
        metadata: {
          ...obj.metadata,
          resourceVersion: (existing as KubernetesObject).metadata?.resourceVersion,
        },
      };
      await api.replace(merged);
      return { action: "replaced" };
    } catch {
      await api.create(obj);
      return { action: "created" };
    }
  }

  // --- Admin -----------------------------------------------------------------

  deleteObject(
    apiVersion: string,
    kind: string,
    name: string,
    namespace: string | undefined,
    context?: string,
  ) {
    return this.objects(context).delete({ apiVersion, kind, metadata: { name, namespace } });
  }

  /** Execute a command in a pod container and collect stdout/stderr. */
  async execInPod(
    name: string,
    namespace: string,
    container: string,
    command: string[],
    context?: string,
  ): Promise<ExecResult> {
    const kc = this.scoped(context);
    const exec = new Exec(kc);
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    const outChunks: Buffer[] = [];
    const errChunks: Buffer[] = [];
    stdout.on("data", (c) => outChunks.push(Buffer.from(c)));
    stderr.on("data", (c) => errChunks.push(Buffer.from(c)));

    return new Promise<ExecResult>((resolve, reject) => {
      exec
        .exec(
          namespace,
          name,
          container,
          command,
          stdout,
          stderr,
          null,
          false,
          (status) => {
            const exitCode =
              status?.status === "Success"
                ? 0
                : typeof (status?.details?.causes?.[0]?.message) === "string"
                  ? Number(status.details.causes[0].message) || 1
                  : 1;
            resolve({
              stdout: Buffer.concat(outChunks).toString("utf8"),
              stderr: Buffer.concat(errChunks).toString("utf8"),
              exitCode,
            });
          },
        )
        .catch(reject);
    });
  }
}
