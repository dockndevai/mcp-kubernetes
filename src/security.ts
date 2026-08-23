/**
 * Security policy engine.
 *
 * Flags decide which tools are registered (capability vs. access mode) and
 * whether each individual call is allowed at runtime (namespace + context
 * scoping, protected namespaces, destructive-op gating, exec gating, dry-run).
 *
 * Pure logic, no I/O, so it is fully unit-testable.
 */

export type Capability = "read" | "write" | "admin";
export type AccessMode = "read-only" | "read-write" | "admin";

const MODE_RANK: Record<AccessMode, number> = {
  "read-only": 0,
  "read-write": 1,
  admin: 2,
};

const CAPABILITY_RANK: Record<Capability, number> = {
  read: 0,
  write: 1,
  admin: 2,
};

export interface SecurityConfig {
  /** Highest capability the server may expose. */
  mode: AccessMode;
  /** If set, only these namespaces may be touched. Empty = all. */
  namespaceAllowlist: string[];
  /** Namespaces that can be read but never mutated or deleted. */
  protectedNamespaces: string[];
  /** If set, only these kube-config contexts may be used. Empty = all. */
  contextAllowlist: string[];
  /** Destructive delete_* operations require this to be true. */
  allowDelete: boolean;
  /** `apply_manifest` (arbitrary object create/replace) requires this. */
  allowApply: boolean;
  /** `exec_in_pod` (run commands in a container) requires this. */
  allowExec: boolean;
  /** Validate + log writes without sending them to the cluster. */
  dryRun: boolean;
  /** Emit a structured JSON audit line to stderr per guarded operation. */
  auditLog: boolean;
}

export class PolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyError";
  }
}

export interface GuardContext {
  tool: string;
  capability: Capability;
  namespace?: string;
  context?: string;
  /** Destructive delete operation — needs allowDelete. */
  destructive?: boolean;
  /** Requires the apply opt-in. */
  requiresApply?: boolean;
  /** Requires the exec opt-in. */
  requiresExec?: boolean;
}

export class SecurityPolicy {
  constructor(private readonly config: SecurityConfig) {}

  get mode(): AccessMode {
    return this.config.mode;
  }

  isCapabilityEnabled(capability: Capability): boolean {
    return CAPABILITY_RANK[capability] <= MODE_RANK[this.config.mode];
  }

  isNamespaceAllowed(ns: string): boolean {
    if (this.config.namespaceAllowlist.length === 0) return true;
    return this.config.namespaceAllowlist.includes(ns);
  }

  isNamespaceProtected(ns: string): boolean {
    return this.config.protectedNamespaces.includes(ns);
  }

  isContextAllowed(ctx: string): boolean {
    if (this.config.contextAllowlist.length === 0) return true;
    return this.config.contextAllowlist.includes(ctx);
  }

  /** Whether the exec tool should even be registered. */
  get execEnabled(): boolean {
    return this.isCapabilityEnabled("admin") && this.config.allowExec;
  }

  guard(ctx: GuardContext): { dryRun: boolean } {
    if (!this.isCapabilityEnabled(ctx.capability)) {
      this.audit(ctx, "DENY", `capability '${ctx.capability}' exceeds mode '${this.config.mode}'`);
      throw new PolicyError(
        `Operation '${ctx.tool}' requires '${ctx.capability}' access but the server runs in '${this.config.mode}' mode.`,
      );
    }

    if (ctx.context !== undefined && !this.isContextAllowed(ctx.context)) {
      this.audit(ctx, "DENY", `context '${ctx.context}' not in allowlist`);
      throw new PolicyError(
        `Context '${ctx.context}' is not in the configured allowlist (K8S_CONTEXT_ALLOWLIST).`,
      );
    }

    if (ctx.namespace !== undefined) {
      if (!this.isNamespaceAllowed(ctx.namespace)) {
        this.audit(ctx, "DENY", `namespace '${ctx.namespace}' not in allowlist`);
        throw new PolicyError(
          `Namespace '${ctx.namespace}' is not in the configured allowlist (K8S_NAMESPACE_ALLOWLIST).`,
        );
      }
      if (ctx.capability !== "read" && this.isNamespaceProtected(ctx.namespace)) {
        this.audit(ctx, "DENY", `namespace '${ctx.namespace}' is protected`);
        throw new PolicyError(
          `Namespace '${ctx.namespace}' is protected (K8S_PROTECTED_NAMESPACES); mutations are refused.`,
        );
      }
    }

    if (ctx.requiresApply && !this.config.allowApply) {
      this.audit(ctx, "DENY", "apply not enabled");
      throw new PolicyError(
        `Operation '${ctx.tool}' is disabled. Set K8S_ALLOW_APPLY=true to enable applying manifests.`,
      );
    }

    if (ctx.requiresExec && !this.config.allowExec) {
      this.audit(ctx, "DENY", "exec not enabled");
      throw new PolicyError(
        `Operation '${ctx.tool}' is disabled. Set K8S_ALLOW_EXEC=true to enable exec into pods.`,
      );
    }

    if (ctx.destructive && !this.config.allowDelete) {
      this.audit(ctx, "DENY", "delete not enabled");
      throw new PolicyError(
        `Destructive operation '${ctx.tool}' is disabled. Set K8S_ALLOW_DELETE=true to enable it.`,
      );
    }

    const dryRun = ctx.capability !== "read" && this.config.dryRun;
    this.audit(ctx, dryRun ? "DRY_RUN" : "ALLOW");
    return { dryRun };
  }

  private audit(ctx: GuardContext, decision: string, reason?: string): void {
    if (!this.config.auditLog) return;
    const line = {
      ts: new Date().toISOString(),
      audit: "kubernetes-mcp",
      decision,
      tool: ctx.tool,
      capability: ctx.capability,
      context: ctx.context ?? null,
      namespace: ctx.namespace ?? null,
      destructive: ctx.destructive ?? false,
      ...(reason ? { reason } : {}),
    };
    process.stderr.write(`${JSON.stringify(line)}\n`);
  }
}
