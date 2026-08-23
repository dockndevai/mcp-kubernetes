#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig } from "./config.js";
import { buildServer } from "./server.js";

async function main(): Promise<void> {
  let config;
  try {
    config = loadConfig();
  } catch (err) {
    process.stderr.write(`[kubernetes-mcp] Configuration error: ${(err as Error).message}\n`);
    process.exit(1);
  }

  let built;
  try {
    built = buildServer(config);
  } catch (err) {
    process.stderr.write(
      `[kubernetes-mcp] Failed to load kube-config: ${(err as Error).message}\n` +
        "Check KUBECONFIG_PATH / K8S_IN_CLUSTER and that a valid kube-config is present.\n",
    );
    process.exit(1);
  }

  process.stderr.write(
    `[kubernetes-mcp] Starting in '${config.security.mode}' mode` +
      `${config.security.dryRun ? " (DRY RUN)" : ""}. ` +
      `${built.enabled.length} tools enabled: ${built.enabled.join(", ")}\n`,
  );

  const transport = new StdioServerTransport();
  await built.server.connect(transport);
}

main().catch((err) => {
  process.stderr.write(`[kubernetes-mcp] Fatal: ${(err as Error).stack ?? err}\n`);
  process.exit(1);
});
