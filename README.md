# mcp-kubernetes

[![CI](https://github.com/dockndevai/mcp-kubernetes/actions/workflows/ci.yml/badge.svg)](https://github.com/dockndevai/mcp-kubernetes/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![npm](https://img.shields.io/npm/v/@dockndevai/mcp-kubernetes)](https://www.npmjs.com/package/@dockndevai/mcp-kubernetes)

A [Model Context Protocol](https://modelcontextprotocol.io) server for **Kubernetes**. It lets an MCP-capable client (Claude Desktop, Claude Code, etc.) inspect and operate Kubernetes clusters across multiple contexts — with behaviour controlled entirely by flags.

The design goal is **safe by default**: it starts read-only, can be scoped to an allowlist of namespaces and contexts, protects system namespaces from mutation, and gates the dangerous operations (delete, apply, exec) behind explicit opt-ins.

## Features

- **Multi-cluster** — every tool accepts an optional `context`; scope which contexts are usable with an allowlist.
- **Access modes** — `read-only` → `read-write` → `admin`, layered so a mode never exposes tools above its level.
- **Security flags** — namespace allowlist, protected namespaces, context allowlist, plus independent opt-ins for delete / apply / exec, dry-run, and JSON audit logging (see below).
- **Standard auth** — uses your kube-config (or in-cluster service account). No credentials are stored by the server.

## Security model

| Concern | Flag | Default | Effect |
| --- | --- | --- | --- |
| What can the server do at all? | `K8S_MODE` | `read-only` | `read-only` exposes only reads; `read-write` adds mutations; `admin` adds destructive tools. Tools above the mode are **never registered**. |
| Which namespaces are in scope? | `K8S_NAMESPACE_ALLOWLIST` | *(all)* | When set, any operation on a namespace outside the list is refused. |
| Which namespaces are read-only forever? | `K8S_PROTECTED_NAMESPACES` | `kube-system,kube-public,kube-node-lease` | Can be read but never mutated or deleted, regardless of mode. |
| Which clusters are reachable? | `K8S_CONTEXT_ALLOWLIST` | *(all)* | When set, only these kube-config contexts may be targeted. |
| Can it delete? | `K8S_ALLOW_DELETE` | `false` | `delete_resource` needs this **and** admin mode. |
| Can it apply manifests? | `K8S_ALLOW_APPLY` | `false` | `apply_manifest` needs this **and** read-write mode. |
| Can it exec into pods? | `K8S_ALLOW_EXEC` | `false` | `exec_in_pod` needs this **and** admin mode; the tool isn't even registered otherwise. |
| Preview without touching the cluster | `K8S_DRY_RUN` | `false` | Write/admin tools validate + log intent, then return without calling the API. |
| Audit trail | `K8S_AUDIT_LOG` | `true` | Emits a JSON line to stderr per guarded operation (`ALLOW` / `DENY` / `DRY_RUN`). |

The layers are independent — e.g. `admin` mode with all three opt-ins `false` can restart and scale deployments but can neither delete resources nor exec into pods.

## Tools

**Read** (`read-only`+): `list_contexts`, `list_namespaces`, `list_pods`, `get_pod`, `get_pod_logs`, `list_deployments`, `list_services`, `list_nodes`, `list_events`, `get_resource`

**Write** (`read-write`+): `scale_deployment`, `restart_deployment`, `set_deployment_image`, `create_namespace`, `apply_manifest` (needs `K8S_ALLOW_APPLY`)

**Admin** (`admin`): `delete_resource` (needs `K8S_ALLOW_DELETE`), `exec_in_pod` (needs `K8S_ALLOW_EXEC`)

## Quickstart — add to your agent

Published on npm as [`@dockndevai/mcp-kubernetes`](https://www.npmjs.com/package/@dockndevai/mcp-kubernetes). No clone or build needed — your MCP client runs it on demand with `npx`. **Start in `read-only` mode**; see [`.env.example`](.env.example) for every variable and [docs/CLIENTS.md](docs/CLIENTS.md) for the full per-client guide.

**Claude Code** (CLI)

```bash
claude mcp add kubernetes -e KUBECONFIG_PATH="/Users/you/.kube/config" -e K8S_MODE="read-only" -- npx -y @dockndevai/mcp-kubernetes
```

**Claude Desktop · Cursor · Windsurf** — same block in `claude_desktop_config.json`, `.cursor/mcp.json`, or `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "kubernetes": {
      "command": "npx",
      "args": [
        "-y",
        "@dockndevai/mcp-kubernetes"
      ],
      "env": {
        "KUBECONFIG_PATH": "/Users/you/.kube/config",
        "K8S_MODE": "read-only"
      }
    }
  }
}
```

**OpenAI Codex CLI** — in `~/.codex/config.toml`:

```toml
[mcp_servers.kubernetes]
command = "npx"
args = ["-y", "@dockndevai/mcp-kubernetes"]
env = { KUBECONFIG_PATH = "/Users/you/.kube/config", K8S_MODE = "read-only" }
```

**VS Code (GitHub Copilot, Agent mode)** — in `.vscode/mcp.json`:

```json
{
  "servers": {
    "kubernetes": {
      "type": "stdio",
      "command": "npx",
      "args": [
        "-y",
        "@dockndevai/mcp-kubernetes"
      ],
      "env": {
        "KUBECONFIG_PATH": "/Users/you/.kube/config",
        "K8S_MODE": "read-only"
      }
    }
  }
}
```

## Run from source (development)

Prefer the published package above. To run from a clone:

```bash
npm install
npm run build
node dist/index.js   # with the environment variables set
```

## Develop

```bash
npm run dev        # watch mode
npm test           # unit tests for the security policy
npm run typecheck
```

## Publishing

This server ships a [`server.json`](server.json) for the official MCP registry and an [`mcpName`](package.json) for npm ownership validation. See **[PUBLISHING.md](PUBLISHING.md)** for publishing to npm and listing on the MCP registry, Smithery, Glama, Cursor, and PulseMCP.

## License

MIT
