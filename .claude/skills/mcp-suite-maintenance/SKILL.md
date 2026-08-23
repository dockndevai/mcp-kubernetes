---
name: mcp-suite-maintenance
description: Maintain and extend the dockndevai MCP server suite (mcp-keycloak, mcp-kubernetes, mcp-oci, mcp-kafka, mcp-clickhouse, mcp-debezium). Use when adding or changing a tool, touching the security/policy layer, bumping dependencies, cutting a release, or publishing to npm or an MCP registry — so the safe-by-default invariants and conventions are preserved.
---

# Maintaining the MCP server suite

These six TypeScript MCP servers share one architecture and one security philosophy: **safe by default, least privilege, never leak secrets**. This skill captures the invariants and the routine tasks so changes stay consistent and safe.

## Shared architecture (every repo)

```
src/
  index.ts        # stdio entrypoint: load config → build server → connect
  server.ts       # registers ONLY tools whose capability ≤ access mode
  config.ts       # env → typed config (connection + security)
  security.ts     # PURE policy engine (SecurityPolicy). No I/O. Unit-tested.
  <domain>/client.ts  # thin wrapper over the real SDK/REST API
  tools/{read,write,admin}.ts  # tool defs tagged with a capability
test/             # vitest — always includes security.test.ts
```

- **Capabilities**: every tool declares `capability: "read" | "write" | "admin"`.
- **Access modes**: `read-only` (0) → `read-write` (1) → `admin` (2). A tool is only registered when `CAPABILITY_RANK[tool] <= MODE_RANK[mode]`. Over-privileged tools are never advertised — this is the primary guarantee.
- **Guard at call time too**: every handler calls `policy.guard({ tool, capability, <resource>, destructive? })` before doing work. Defence in depth on top of registration.

## Non-negotiable invariants (do NOT regress these)

1. **Read-only means read-only.** A tool tagged `read` must never mutate. If it can mutate, it is `write` or `admin`.
2. **Destructive ops need a second opt-in.** Deletes/drops require the mode **and** an explicit flag (`*_ALLOW_DELETE`, `OCI_ALLOW_APPLY`, `K8S_ALLOW_EXEC`, etc.). The most dangerous (k8s `exec_in_pod`) is not even registered without its flag.
3. **Protected resources are read-only forever.** System realms/namespaces/databases/internal topics can be read but never mutated, regardless of mode.
4. **Secrets never reach the model.** Redact before returning (see `redact.ts` in mcp-oci / mcp-debezium; `reset_password` never echoes; `list_clients` strips secrets; ClickHouse caps rows). Any new field that could carry a credential must be redacted.
5. **Audit + dry-run apply to every write.** `guard()` emits the audit line and returns `{ dryRun }`; write handlers must honor `dryRun` by returning intent without calling the backend.
6. **stdout belongs to MCP.** All logs/audit/warnings go to **stderr** only. Never `console.log` to stdout.

## Adding or changing a tool (checklist)

1. Put it in the right file by capability: `tools/read.ts` / `write.ts` / `admin.ts`.
2. Give it a zod `inputSchema` with `.describe()` on every field (the model reads these).
3. First line of the handler: `const { dryRun } = policy.guard({ tool, capability, <resource>, destructive })`.
4. For writes: `if (dryRun) return textResult("[dry-run] Would …")` before any backend call.
5. Redact the result if it can contain secrets.
6. Add/extend a unit test in `test/security.test.ts` (and the domain test if pure logic changed).
7. Update the README tool list, `.env.example` (if a new flag), and `server.json` env vars (if a new required/secret var).
8. `npm run typecheck && npm test && npm run build` must all pass.

## Adding a new server to the suite

Copy the smallest existing server (mcp-debezium is a good REST template; mcp-kafka for an SDK client), then:
- keep `security.ts` shape; rename the scoped resource (realm/namespace/topic/database/connector).
- keep `read-only` the default, protected defaults sensible, deletes gated.
- mirror the docs set: `README.md`, `SECURITY.md`, `.env.example`, `docs/CLIENTS.md`, `server.json`, CI, MIT `LICENSE`.

## Dependency & release maintenance

- `npm outdated`; bump `@modelcontextprotocol/sdk`, the domain SDK, zod, and vitest deliberately. Re-run typecheck+test+build.
- `npm audit` should be **0 vulnerabilities** — dev-only advisories (vite/esbuild) are cleared by keeping vitest current.
- Version bumps are semver in `package.json` **and** `server.json` (`version` and each package `version` must match). Tag releases.
- CI (`.github/workflows/ci.yml`) runs typecheck → test → build on push/PR; keep it green.

## Publishing (see the repo's PUBLISHING.md for exact commands)

Before any publish: green CI, README/`.env.example`/`server.json` in sync, `dist/` builds, version bumped, secrets scrubbed from examples.
- **npm**: `npm publish --access public` (the `prepublishOnly` build guard runs first). `package.json` carries `mcpName` for registry ownership validation.
- **Official MCP registry**: `mcp-publisher` with `server.json` (namespace `io.github.dockndevai/…`).
- **Smithery / Glama / Cursor directory / PulseMCP**: mostly index public GitHub repos automatically; keep README + `server.json` accurate.

## Operator best practices (put these in front of users)

- Start every server in `read-only`; raise the mode only for a specific task, then lower it again.
- Scope with the backend's own RBAC/ACLs/IAM first — the flags are defence in depth, not the primary control.
- Use allowlists (`*_ALLOWLIST`) to pin the blast radius to the exact realms/namespaces/topics/databases/connectors intended.
- Leave `*_AUDIT_LOG=true`; ship the stderr audit lines to your logging pipeline.
- Preview risky changes with `*_DRY_RUN=true` before enabling the real write.
