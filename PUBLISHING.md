# Publishing `mcp-kubernetes`

This server is a standard **stdio** MCP server distributed as an npm package. Below is how to publish it and list it in the MCP marketplaces/registries. Run these from your own accounts — they require credentials this repo does not contain.

## 0. Pre-flight

- [ ] CI is green (typecheck + tests + build).
- [ ] `version` matches in `package.json` **and** `server.json`.
- [ ] `README.md`, `.env.example`, and `server.json` list the same env vars.
- [ ] No secrets in examples; `dist/` builds cleanly (`npm run build`).

## 1. npm (the base everything else builds on)

```bash
npm login
npm publish --access public   # prepublishOnly runs the build first
```

`package.json` already declares `"mcpName": "io.github.dockndevai/mcp-kubernetes"`, which the official registry uses to verify npm ownership. After this, clients can run the server with `npx -y mcp-kubernetes` (no local clone needed).

## 2. Official MCP Registry (registry.modelcontextprotocol.io)

The canonical, open registry. Uses `server.json` (already in this repo) and the `mcp-publisher` CLI, with the `io.github.dockndevai/*` namespace verified via GitHub login.

```bash
# Install the publisher CLI (see modelcontextprotocol.io/registry docs for the latest install method)
mcp-publisher login github        # verifies the io.github.dockndevai namespace
mcp-publisher publish             # reads ./server.json
```

## 3. Smithery (smithery.ai)

Smithery indexes GitHub MCP servers and can host/run them. Connect the GitHub repo at smithery.ai, or add a `smithery.yaml` describing the stdio command. Because this is an npm stdio server, the runtime command is `npx -y mcp-kubernetes`.

## 4. Glama (glama.ai/mcp/servers)

Glama **auto-discovers** public GitHub MCP servers — often no action needed. To improve the listing, keep the README and `server.json` accurate; an optional `glama.json` can add metadata.

## 5. Cursor MCP directory (cursor.com/directory)

Submit via the Cursor directory site. Provide the install command; the "Add to Cursor" deep link uses the same stdio config shown in [docs/CLIENTS.md](docs/CLIENTS.md).

## 6. PulseMCP, mcp.so, and Awesome MCP Servers

These are community catalogs that index public servers. Submit the repo URL (PulseMCP, mcp.so) or open a PR to the `punkpeye/awesome-mcp-servers` list. A clear README + `server.json` is all they need.

## Automated releases (git tags)

A GitHub Actions workflow ([`.github/workflows/release.yml`](.github/workflows/release.yml)) publishes on version tags. One-time setup, then every release is a tag push.

**One-time setup**

1. Create an npm **automation** access token (npmjs.com → Access Tokens → Granular/Automation).
2. Add it as a repo secret:
   ```bash
   gh secret set NPM_TOKEN --repo dockndevai/mcp-kubernetes
   ```
   (Or set it once as an organization secret shared across all the servers.)
3. *(Optional)* to also publish to the official MCP Registry on each release, set a repo variable:
   ```bash
   gh variable set PUBLISH_TO_MCP_REGISTRY --repo dockndevai/mcp-kubernetes --body true
   ```
   This uses passwordless GitHub OIDC for the `io.github.dockndevai` namespace — no extra secret.

**Cutting a release**

```bash
npm version patch      # bumps package.json, commits, creates the vX.Y.Z tag
# also bump "version" in server.json to match, then amend if needed
git push --follow-tags
```

The workflow verifies the tag matches `package.json` **and** `server.json`, runs typecheck + tests + build, then `npm publish --provenance --access public`, creates a GitHub Release with generated notes, and (if enabled) publishes to the MCP Registry.

## Notes

- Registries generally require a **public GitHub repo** and (for run-from-npm) a **published npm package** — do step 1 first.
- Keep one source of truth: bump `version` in `package.json` and `server.json` together, then re-publish to npm and the official registry; the GitHub-indexing catalogs refresh on their own.
