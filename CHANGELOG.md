# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-11-11

### Security
- Strict mode (`*_REQUIRE_HUMAN_APPROVAL`) now refuses an action whose target's version cannot be read (it used to proceed unpinned), and the approval prompt no longer calls reversible changes (moves, config changes) irreversible.
- **Approval prompts are fully reviewable.** Arguments are shown in full up to 16 000 characters (previously cut at 1500, so a padded prefix could hide the tail of a long statement); a longer action is refused instead of approved blind. Secret redaction in prompts matches whole words (`bypass`/`tokenizer` are no longer shown as `[redacted]`).
- **Approval no longer fails open on timeout.** The human-approval prompt used the MCP SDK's default
  60 s request timeout, and a timeout fell through to "approved" (the `K8S_ALLOW_DELETE` / `K8S_ALLOW_EXEC` /
  `K8S_ALLOW_APPLY` gate had already passed). A prompt nobody answered therefore auto-approved a destructive
  operation. A timeout is now a refusal, and the wait defaults to 5 minutes.
- **Protected-namespace and allowlist checks no longer skipped for namespace-scoped targets.** `delete_resource`
  with kind `Namespace` and no `namespace` argument passed `undefined` to the policy, so `kube-system` could be
  deleted with only admin mode and `K8S_ALLOW_DELETE` (and a harmless `namespace` argument next to a protected
  name had the same effect). A `Namespace`'s own name is now what the policy checks, in `delete_resource`,
  `get_resource` and `apply_manifest`; a namespaced kind with no (or an empty) namespace is checked against the
  kube-config context's default namespace, which is where the request actually lands.
- **`get_resource` no longer returns Secret values.** `data` and `stringData` are replaced with
  `<redacted, N bytes>` (keys kept) and the `last-applied-configuration` annotation is redacted.
- `apiVersion` in `get_resource` / `delete_resource` / `apply_manifest` is validated (`v1` or `<group>/<version>`)
  before it is used to build a request.

### Added
- **Approvals are bound to the exact action.** The prompt shows the tool, the full (secret-redacted)
  arguments and a fingerprint; every approval and refusal is written to the audit log as
  `"audit":"approval"` with the fingerprint, resource version and `approvedBy` (`human` / `flag-only`).
  This also applies to the prompts raised by the optional laya-guard integration.
- **Approvals are bound to the target's version.** `delete_resource`, `exec_in_pod`, `apply_manifest` and
  `scale_deployment` (to 0) read the target's `metadata.uid` + `metadata.resourceVersion` before the prompt and
  again after the human answers, and refuse if it changed (including a delete + recreate under the same name).
- `delete_resource` passes the approved uid and resourceVersion to the API server as delete preconditions;
  `apply_manifest` refuses to replace an object that no longer matches the approved version.
- `K8S_REQUIRE_HUMAN_APPROVAL=true` — refuse destructive ops when the client cannot elicit.
- `delete_resource` on a namespace asks the human to type the namespace name.

### Changed
- `apply_manifest` no longer retries a failed replace as a create; an error from the replace is now reported as is.

Tracking issue: https://github.com/dockndevai/mcp-core/issues/1

## [0.3.5] - 2026-11-09

### Changed
- Routine dependency/security maintenance. `npm audit --audit-level=high` reported 0
  high/critical advisories; no `npm audit fix` was needed.
- Took safe in-range patch bumps: `@kubernetes/client-node` ^2.0.0 2.0.1 → 2.0.2,
  `vitest` ^5.0.5 5.0.5 → 5.1.0.
- No direct dependency crossed a major version boundary; `npm run typecheck`, `npm run build`,
  and `npm test` all pass; final `npm audit` is clean.

## [0.3.4] - 2026-11-02

### Changed
- Routine dependency/security maintenance. `npm audit --audit-level=high` reported 0
  high/critical advisories; a moderate `@hono/node-server` advisory (transitive via
  `@modelcontextprotocol/sdk`) was cleared via `npm audit fix` (2.1.1 → 2.1.5, no direct
  dependency change). Final `npm audit` is clean (0 vulnerabilities).
- Took a safe in-range patch bump: `@types/node` ^26.5.0 26.6.5 → 26.6.6.
- No direct dependency crossed a major version boundary; `npm run typecheck`, `npm run build`,
  and `npm test` all pass.

## [0.3.3] - 2026-10-26

### Changed
- Routine dependency/security maintenance. `npm audit --audit-level=high` reported 2 high and
  2 moderate advisories (transitive `body-parser`, `fast-uri`, `hono`, `undici`), all resolved
  via `npm audit fix` with no direct dependency changes; `npm audit` now reports 0 vulnerabilities.
- Took safe in-range patch bumps: `@kubernetes/client-node` ^2.0.0 2.0.0 → 2.0.1,
  `@modelcontextprotocol/sdk` ^1.30.0 1.32.1 → 1.32.2.
- No direct dependency crossed a major version boundary; `npm run typecheck`, `npm run build`,
  and `npm test` all pass; final `npm audit` is clean.

## [0.3.2] - 2026-10-19

### Changed
- Routine dependency/security maintenance. `npm audit --audit-level=high` reported 0
  vulnerabilities both before and after this pass (no high/critical advisories to fix).
- Took safe in-range patch bumps: `zod` ^4.6.6 → ^4.6.7, `vitest` ^5.0.3 → ^5.0.5.
- No direct dependency crossed a major version boundary; `npm run typecheck`, `npm run build`,
  and `npm test` all pass; final `npm audit` is clean.

## [0.3.1] - 2026-10-12

### Fixed
- Dependency/security maintenance: resolved 6 npm audit advisories (1 critical, 4 high, 1
  moderate) via `npm audit fix`, including `proxy-addr` (critical IP-spoofing via IPv4-mapped
  IPv6 trust subnet), `@modelcontextprotocol/sdk` (high — OAuth client could be redirected to
  send credentials to an attacker-chosen authorization server), `undici` (high — multiple DoS
  and cache-poisoning advisories), `fast-uri` (high — authority injection / host confusion /
  host-case normalization), `source-map-js` (high — event-loop DoS), and `ip-address`
  (moderate — SSRF/trust-boundary bypass). `npm audit` now reports 0 vulnerabilities.
- Took safe in-range patch/minor bumps for `@types/node`, `tsx`, `vitest`, and `zod`.

## [0.3.0] - 2026-09-27

### Added
- **Optional AI risk guard (laya-guard).** `delete_resource`, `exec_in_pod` and `apply_manifest` can
  consult a local [laya-guard](https://github.com/dockndevai/laya-guard) daemon that classifies the
  operation allow / confirm / block before it runs. Runs *after* the delete/exec/apply gates and can
  only *tighten*, never grant; fails closed. Off by default (`K8S_GUARD_MODE=monitor|enforce`).

## [0.2.2] - 2026-09-12

### Changed
- Bring dependencies and CI to current majors: `zod` ^4, TypeScript ^7, `@types/node` ^26, `tsx` ^4.23, and GitHub Actions (checkout v7, setup-node v7, action-gh-release v3, gitleaks v3, codeql-action v4). Clears the open Dependabot updates; `npm audit` reports 0 vulnerabilities.

## [0.2.1] - 2026-09-10

### Added
- Extend interactive confirmation (MCP elicitation) to `scale_deployment` **when scaling to 0** (which takes the workload offline).

## [0.2.0] - 2026-09-10

### Added
- **Human-in-the-loop confirmation for destructive actions**, via MCP [elicitation](https://modelcontextprotocol.io/specification/draft/client/elicitation). When the connected client supports elicitation, `delete_resource`, `exec_in_pod`, and `apply_manifest` now pause and ask the **human** to approve the exact action before it runs — a model can echo a confirmation string, but it cannot approve a prompt shown to the user. Clients that don't advertise elicitation fall back to the existing `*_ALLOW_*` flag gate, so enabling this is never *more* permissive than before.

## [0.1.3] - 2026-09-09

### Changed
- Require **Node 22** (previously Node 20); the updated dependency tree needs Node ≥ 22.19. CI and release workflows, the Dockerfile base image, and `engines` were updated.
- Bump `@kubernetes/client-node` → ^2.0.0, `zod` → ^4, `typescript` → ^7, and `@types/node` → ^26 (Dependabot group). Update the `apply_manifest` input schema to `z.record(z.string(), z.any())` for zod 4.
- Bump the test runner `vitest` to ^5.0.0.

### Security
- Refresh the dependency tree to clear the moderate `hono` and `qs` advisories (transitive via the MCP SDK's HTTP transport, unused by this stdio server) and the `vitest` advisory; `npm audit` now reports **0 vulnerabilities**.

## [0.1.2] - 2026-08-30

### Changed
- Bump `@modelcontextprotocol/sdk` to ^1.30.0 to clear known dependency advisories flagged by supply-chain scanners.

## [0.1.1] - 2026-08-28

### Added
- MCP **tool annotations** on every tool (`readOnlyHint`, `destructiveHint`,
  `idempotentHint`, `openWorldHint`), derived from each tool's access
  capability. Hosts can now reason about a tool's safety from structured
  metadata instead of parsing the description — read tools are advertised as
  read-only and non-destructive, admin/destructive tools as mutating.
- A test that keeps the annotations consistent with each tool's capability.

## [0.1.0]

### Added
- Initial release.
