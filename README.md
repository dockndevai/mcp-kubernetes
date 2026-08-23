# mcp-kubernetes

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

## Install

```bash
npm install
npm run build
```

## Run with Claude Desktop / Claude Code

Add to your MCP client configuration:

```json
{
  "mcpServers": {
    "kubernetes": {
      "command": "node",
      "args": ["/absolute/path/to/mcp-kubernetes/dist/index.js"],
      "env": {
        "KUBECONFIG_PATH": "/Users/you/.kube/config",
        "K8S_MODE": "read-only",
        "K8S_CONTEXT_ALLOWLIST": "staging",
        "K8S_NAMESPACE_ALLOWLIST": "app,web"
      }
    }
  }
}
```

Bump `K8S_MODE` to `read-write` for scaling/restarts, and to `admin` (plus the relevant `K8S_ALLOW_*` flag) only when you intend to allow deletes or exec.

## Develop

```bash
npm run dev        # watch mode
npm test           # unit tests for the security policy
npm run typecheck
```

## License

MIT
