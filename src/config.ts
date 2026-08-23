/**
 * Configuration from environment variables. Cluster connection details come
 * from a standard kube-config (KUBECONFIG or ~/.kube/config, or in-cluster).
 */
import type { AccessMode, SecurityConfig } from "./security.js";

export interface KubeConnection {
  /** Explicit path to a kube-config file. Empty = default resolution. */
  kubeconfigPath?: string;
  /** Load in-cluster config (service account) instead of a kube-config file. */
  inCluster: boolean;
  /** Default context to use when a tool call omits one. Empty = current-context. */
  defaultContext?: string;
}

export interface AppConfig {
  connection: KubeConnection;
  security: SecurityConfig;
}

const DEFAULT_PROTECTED = ["kube-system", "kube-public", "kube-node-lease"];

function bool(name: string, fallback: boolean): boolean {
  const v = process.env[name];
  if (v === undefined || v === "") return fallback;
  return ["1", "true", "yes", "on"].includes(v.toLowerCase());
}

function list(name: string): string[] {
  const v = process.env[name];
  if (!v) return [];
  return v
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function parseMode(): AccessMode {
  const raw = (process.env.K8S_MODE ?? "read-only").toLowerCase();
  if (raw === "read-only" || raw === "read-write" || raw === "admin") return raw;
  throw new Error(`Invalid K8S_MODE '${raw}'. Expected one of: read-only, read-write, admin.`);
}

export function loadConfig(): AppConfig {
  const protectedNs = list("K8S_PROTECTED_NAMESPACES");
  return {
    connection: {
      kubeconfigPath: process.env.KUBECONFIG_PATH || undefined,
      inCluster: bool("K8S_IN_CLUSTER", false),
      defaultContext: process.env.K8S_CONTEXT || undefined,
    },
    security: {
      mode: parseMode(),
      namespaceAllowlist: list("K8S_NAMESPACE_ALLOWLIST"),
      protectedNamespaces: protectedNs.length ? protectedNs : DEFAULT_PROTECTED,
      contextAllowlist: list("K8S_CONTEXT_ALLOWLIST"),
      allowDelete: bool("K8S_ALLOW_DELETE", false),
      allowApply: bool("K8S_ALLOW_APPLY", false),
      allowExec: bool("K8S_ALLOW_EXEC", false),
      dryRun: bool("K8S_DRY_RUN", false),
      auditLog: bool("K8S_AUDIT_LOG", true),
    },
  };
}
