import { describe, expect, it } from "vitest";
import { redactList, redactSecret } from "../src/k8s/redact.js";

describe("redactSecret", () => {
  it("replaces Secret data values with a size marker, keeping the keys", () => {
    const secret = {
      kind: "Secret",
      metadata: { name: "db-creds", namespace: "app" },
      data: {
        password: Buffer.from("super-secret-password").toString("base64"),
        username: Buffer.from("admin").toString("base64"),
      },
    };
    const result = redactSecret(secret);
    expect(result.data).toEqual({
      password: `<redacted, ${Buffer.byteLength("super-secret-password")} bytes>`,
      username: `<redacted, ${Buffer.byteLength("admin")} bytes>`,
    });
    // Original object is untouched.
    expect(secret.data.password).not.toMatch(/redacted/);
    // No key or value in the output decodes back to the plaintext secret.
    expect(JSON.stringify(result)).not.toContain("super-secret-password");
  });

  it("leaves non-Secret objects untouched", () => {
    const pod = { kind: "Pod", metadata: { name: "web" }, data: { foo: "YmFy" } };
    expect(redactSecret(pod)).toEqual(pod);
  });

  it("leaves a Secret with no data untouched", () => {
    const secret = { kind: "Secret", metadata: { name: "empty" } };
    expect(redactSecret(secret)).toEqual(secret);
  });

  it("passes through objects with no kind (e.g. a plain map) safely", () => {
    const obj = { data: { x: "eQ==" } };
    expect(redactSecret(obj)).toEqual(obj);
  });
});

describe("redactList", () => {
  it("redacts every Secret in a list while leaving other kinds alone", () => {
    const list = {
      items: [
        { kind: "Secret", metadata: { name: "s1" }, data: { k: Buffer.from("v1").toString("base64") } },
        { kind: "ConfigMap", metadata: { name: "c1" }, data: { k: "plain-ok" } },
      ],
    };
    const result = redactList(list);
    expect(result.items?.[0].data).toEqual({ k: `<redacted, 2 bytes>` });
    expect(result.items?.[1].data).toEqual({ k: "plain-ok" });
  });

  it("passes through a response with no items array unchanged", () => {
    const notAList = { kind: "Status", message: "ok" };
    expect(redactList(notAList)).toEqual(notAList);
  });
});
