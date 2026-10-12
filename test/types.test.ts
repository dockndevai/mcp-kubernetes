import { describe, expect, it } from "vitest";
import { redactIfSecret } from "../src/tools/types.js";

describe("redactIfSecret", () => {
  it("redacts Secret data values but keeps key names", () => {
    const secret = {
      apiVersion: "v1",
      kind: "Secret",
      metadata: { name: "db-creds", namespace: "app" },
      type: "Opaque",
      data: { username: "YWRtaW4=", password: "c3VwZXJzZWNyZXQ=" }, // gitleaks:allow -- fake fixture, not a real credential
    };
    const out = redactIfSecret("Secret", secret) as typeof secret;
    expect(out.data).toEqual({ username: "***redacted***", password: "***redacted***" });
    expect(out.metadata).toEqual(secret.metadata);
  });

  it("redacts stringData too, and is case-insensitive on kind", () => {
    const secret = {
      kind: "secret",
      stringData: { token: "raw-value" },
    };
    const out = redactIfSecret("secret", secret) as typeof secret;
    expect(out.stringData).toEqual({ token: "***redacted***" });
  });

  it("leaves non-Secret kinds untouched", () => {
    const configMap = { kind: "ConfigMap", data: { "app.conf": "key=value" } };
    expect(redactIfSecret("ConfigMap", configMap)).toEqual(configMap);
  });

  it("is a no-op when data/stringData are absent", () => {
    const secret = { kind: "Secret", metadata: { name: "empty" } };
    expect(redactIfSecret("Secret", secret)).toEqual(secret);
  });
});
