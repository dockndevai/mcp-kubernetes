# Security

`mcp-kubernetes` exposes cluster operations to an AI agent. Treat it like any
other privileged automation and grant it the least access it needs.

## Principles

- **Start read-only.** Leave `K8S_MODE=read-only` until you specifically need the
  agent to make changes. Tools above the current mode are never registered, so a
  read-only server cannot mutate anything even if asked.
- **Scope with RBAC, not just flags.** The flags are defence in depth; the
  primary control is the kube-config / service-account RBAC. Bind the identity to
  a `Role`/`ClusterRole` that grants only what you intend.
- **Protect system namespaces.** `kube-system`, `kube-public`, and
  `kube-node-lease` are protected by default and can be read but never mutated.
  Add more via `K8S_PROTECTED_NAMESPACES`.
- **Pin the blast radius.** Use `K8S_NAMESPACE_ALLOWLIST` and
  `K8S_CONTEXT_ALLOWLIST` to constrain which namespaces and clusters are reachable.
- **Gate the dangerous verbs explicitly.** `delete_resource` needs
  `K8S_ALLOW_DELETE`, `apply_manifest` needs `K8S_ALLOW_APPLY`, and `exec_in_pod`
  needs `K8S_ALLOW_EXEC` — each on top of the required mode. `exec_in_pod` is not
  even registered unless its flag is set.
- **Require a human for destructive ops.** Set `K8S_REQUIRE_HUMAN_APPROVAL=true` so `delete_resource`,
  `exec_in_pod`, `apply_manifest` and scale-to-zero are refused when the client cannot show an approval
  prompt. Each approval is bound to the exact tool and arguments (fingerprint) and to the target object's
  `metadata.uid` + `metadata.resourceVersion` (for `exec_in_pod`, the pod's; for `apply_manifest`, the
  existing object's, or "absent" when it will be created); if the object changed while the human was
  deciding, the action is refused. `delete_resource` also sends the approved uid and resourceVersion to the
  API server as delete preconditions. Deleting a namespace also asks the human to type its name. Any write
  to the object, including controller status updates, changes its resourceVersion, so a busy object may
  need the action re-issued. Approval receipts are written to the audit log (`"audit":"approval"`, with
  `approvedBy` = `human` or `flag-only`).
- **Preview with dry-run.** `K8S_DRY_RUN=true` validates and logs write intent
  without contacting the cluster.
- **Keep the audit log on.** `K8S_AUDIT_LOG=true` (default) writes a JSON line per
  guarded operation to stderr.

## Handling of credentials

- The server uses your kube-config or in-cluster service account; it stores no
  credentials of its own.
- `exec_in_pod` is powerful (arbitrary in-container commands). Enable it only for
  trusted, tightly-scoped clusters.

## Reporting a vulnerability

Please open a private security advisory on the GitHub repository rather than a
public issue.
