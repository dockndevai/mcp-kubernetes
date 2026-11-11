import { describe, expect, it } from "vitest";
import { redactLogText } from "../src/redact.js";

// Credential-shaped fixtures are assembled at run time so this file itself carries no literal token or key that a
// secret scanner would flag.
// The mask is written `<M>` in expectations so a secret-named key followed by the marker never sits in the source,
// where a secret scanner reads it as a hard-coded credential.
const M = (s: string) => s.replaceAll("<M>", "[REDACTED]");
const j = (...parts: string[]) => parts.join("");
const A = j("abcDEF", "123456");
const C = j("Zm9vYmFyYmF6", "%2Bq");
const D = j("Zm9vYmFy", "YmF6");
const E = j("Zm9vYmFy", "+/abc==");
const F = j("0123456789abcdef", "0123456789abcdef");
const b64u = (s: string) => Buffer.from(s).toString("base64url");
const JWT = j(b64u('{"alg":"RS256","typ":"JWT"}'), ".", b64u('{"iss":"kubernetes/serviceaccount","sub":"system:serviceaccount:shop:web"}'), ".", b64u("signature-bytes-signature-bytes"));
const OCP_TOKEN = j("sha256", "~", "Yq3Zk8vN1mWcT5hJd2LpR7sXaB9fGeUo4iVnC6tQyHw");
const AWS_KEY_ID = j("AKIA", "ABCDEFGHIJKLMNOP");
const AWS_SECRET = j("wJalrXUtnFEMI", "/K7MDENG/bPxRfiCY", "EXAMPLEKEY");
const GH_TOKEN = j("gh", "p_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8");
const GCP_KEY = j("AI", "zaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q");
const SLACK = j("xo", "xb-", "1234567890-abcdefghijkl");
const STRIPE = j("sk", "_live_", "4eC39HqLyjWDarjtT1zdp7dc");
const PEM_HEAD = (kind = "") => j("-----BEGIN ", kind, "PRIVATE KEY-----");
const PEM_FOOT = (kind = "") => j("-----END ", kind, "PRIVATE KEY-----");
const BODY1 = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj";
const BODY2 = "MBGWRPZ0YyMgE0TtHn3kXKHk0YEFc5qS9eNsD4E7vUQ1o1pM8yq2lJf6tbAAA=";

function gone(out: string, ...secrets: string[]) {
  for (const s of secrets) expect(out, `leaked: ${s}`).not.toContain(s);
}

describe("redactLogText: key/value pairs", () => {
  it.each([
    ["password=hunter2hunter2", "password=<M>", "hunter2hunter2"],
    ["db_password=hunter2hunter2 retries=3", "db_password=<M> retries=3", "hunter2hunter2"],
    ["DB_PASSWORD: hunter2hunter2", "DB_PASSWORD: <M>", "hunter2hunter2"],
    ["passwd: hunter2hunter2", "passwd: <M>", "hunter2hunter2"],
    ["PASSWD = hunter2hunter2", "PASSWD = <M>", "hunter2hunter2"],
    ["passphrase=correct horse", "passphrase=<M> horse", "correct"],
    ["Password:hunter2hunter2", "Password:<M>", "hunter2hunter2"],
    [`client_secret=${A}`, "client_secret=<M>", `${A}`],
    [`clientSecret: ${A}`, "clientSecret: <M>", `${A}`],
    [`api_key=${A}&x=1`, "api_key=<M>&x=1", `${A}`],
    [`X-Api-Key: ${A}`, "X-Api-Key: <M>", `${A}`],
    [`access_token=${A}`, "access_token=<M>", `${A}`],
    [`GET /cb?code=1&access_token=${A}&state=x`, "GET /cb?code=1&access_token=<M>&state=x", `${A}`],
    [`AWS_SESSION_TOKEN=${A}`, "AWS_SESSION_TOKEN=<M>", `${A}`],
    [`secret_key=${A}`, "secret_key=<M>", `${A}`],
    [`aws_secret_access_key = ${AWS_SECRET}`, "aws_secret_access_key = <M>", AWS_SECRET],
    ["private_key: s3cretvalue", "private_key: <M>", "s3cretvalue"],
    ["credentials=user:s3cretvalue", "credentials=<M>", "s3cretvalue"],
    ["Server=db;User Id=sa;Password=s3cr3t!Pass;Encrypt=true", "Server=db;User Id=sa;Password=<M>;Encrypt=true", "s3cr3t!Pass"],
    [`AccountName=acct;AccountKey=${E};EndpointSuffix=core.windows.net`, "AccountName=acct;AccountKey=<M>;EndpointSuffix=core.windows.net", "Zm9vYmFy"],
    [`SharedAccessKey=${D}`, "SharedAccessKey=<M>", `${D}`],
    [`https://acct.blob.core.windows.net/c/b?sv=2022&sig=${C}&se=2030`, "https://acct.blob.core.windows.net/c/b?sv=2022&sig=<M>&se=2030", `${D}`],
    [`X-Amz-Signature=${F}`, "X-Amz-Signature=<M>", "0123456789abcdef"],
    ["started with --password hunter2hunter2 --verbose", "started with --password <M> --verbose", "hunter2hunter2"],
    ["started with --db-password=hunter2hunter2", "started with --db-password=<M>", "hunter2hunter2"],
    ["map[password:hunter2hunter2 user:bob]", "map[password:<M> user:bob]", "hunter2hunter2"],
    ["cfg{password => 'hunter2hunter2'}", "cfg{password => '<M>'}", "hunter2hunter2"],
  ])("%s", (input, expected, secret) => {
    const out = redactLogText(input);
    expect(out).toBe(M(expected));
    gone(out, secret);
  });

  it("handles JSON and escaped-JSON log lines, keeping keys, quotes and other fields", () => {
    const out = redactLogText(`{"level":"info","user":"bob","password":"hunter2hunter2","client_secret":"${A}","n":5}`);
    expect(out).toBe(M('{"level":"info","user":"bob","password":"<M>","client_secret":"<M>","n":5}'));
    expect(JSON.parse(out).user).toBe("bob");
    const nested = redactLogText('{"msg":"{\\"password\\":\\"hunter2hunter2\\",\\"ok\\":true}"}');
    gone(nested, "hunter2hunter2");
    expect(nested).toContain("ok");
    const unterminated = redactLogText('login body: {"password": "hunter2hunter2 and more');
    gone(unterminated, "hunter2hunter2");
  });

  it("masks every pair on one line", () => {
    const out = redactLogText("password=aaaaaaaa token=bbbbbbbb secret=cccccccc");
    expect(out).toBe(M("password=<M> token=<M> secret=<M>"));
  });
});

describe("redactLogText: Authorization headers and bearer tokens", () => {
  it.each([
    ["Authorization: Bearer abc123DEF456ghi789", "Authorization: Bearer <M>", "abc123DEF456ghi789"],
    ["authorization=bearer abc123DEF456ghi789", "authorization=bearer <M>", "abc123DEF456ghi789"],
    ["Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA==", "Proxy-Authorization: Basic <M>", "dXNlcjpwYXNzd29yZA"],
    ["Authorization: Token abc123DEF456ghi789", "Authorization: Token <M>", "abc123DEF456ghi789"],
    ["Authorization: abc123DEF456ghi789", "Authorization: <M>", "abc123DEF456ghi789"],
    ['"Authorization":"Bearer abc123DEF456ghi789"', '"Authorization":"Bearer <M>"', "abc123DEF456ghi789"],
    ["headers=map[Authorization:[Bearer abc123DEF456ghi789] Accept:[*/*]]", "headers=map[Authorization:[Bearer <M> Accept:[*/*]]", "abc123DEF456ghi789"],
    [`curl -H "Authorization: Bearer ${GH_TOKEN}" https://api.example.com`, 'curl -H "Authorization: Bearer <M>" https://api.example.com', GH_TOKEN],
    ["Authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20300101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=0123456789abcdef", "Authorization: AWS4-HMAC-SHA256 <M>", "0123456789abcdef"],
    ["using Bearer abc123DEF456ghi789 for the call", "using Bearer <M> for the call", "abc123DEF456ghi789"],
    ["sent bearer abc123DEF456ghi789", "sent bearer <M>", "abc123DEF456ghi789"],
  ])("%s", (input, expected, secret) => {
    const out = redactLogText(input);
    expect(out).toBe(M(expected));
    gone(out, secret);
  });

  it("does not treat the English word 'bearer' as a token prefix", () => {
    for (const l of ["bearer authentication is not enabled", "the bearer of this note", "Bearer realm=example"]) expect(redactLogText(l)).toBe(l);
  });
});

describe("redactLogText: credentials in URLs", () => {
  it.each([
    ["connecting to postgres://app:s3cr3tPass@db.shop.svc:5432/orders?sslmode=disable", "connecting to postgres://app:<M>@db.shop.svc:5432/orders?sslmode=disable", "s3cr3tPass"],
    ["mongodb+srv://admin:p%40ss%3Aword@cluster0.example.net/db", "mongodb+srv://admin:<M>@cluster0.example.net/db", "p%40ss"],
    ["redis://:s3cr3tPass@cache:6379/0", "redis://:<M>@cache:6379/0", "s3cr3tPass"],
    [`git clone https://x-access-token:${A}@github.com/o/r.git`, "git clone https://x-access-token:<M>@github.com/o/r.git", `${A}`],
    ["amqp://u:pa@ss@rabbit:5672/", "amqp://u:<M>@rabbit:5672/", "pa@ss"],
    ['{"url":"https://u:s3cr3tPass@h.example/x"}', '{"url":"https://u:<M>@h.example/x"}', "s3cr3tPass"],
    ["a https://u1:pw1pw1pw@h1/x and https://u2:pw2pw2pw@h2/y", "a https://u1:<M>@h1/x and https://u2:<M>@h2/y", "pw1pw1pw"],
  ])("%s", (input, expected, secret) => {
    const out = redactLogText(input);
    expect(out).toBe(M(expected));
    gone(out, secret);
  });

  it("leaves URLs without a password alone", () => {
    for (const l of [
      "GET http://localhost:8080/healthz",
      "clone ssh://git@github.com/o/r.git",
      "https://example.com/users/bob@example.com/profile",
      "dial tcp [::1]:6443: connect: connection refused http://[::1]:6443/x",
      "https://example.com:8443/path?next=http://other:80/",
    ])
      expect(redactLogText(l)).toBe(l);
  });
});

describe("redactLogText: well-known token shapes (no key name needed)", () => {
  it.each([
    ["service-account JWT", `token from file: ${JWT}`, "[REDACTED:jwt]", JWT],
    ["JWT in quotes", `{"id_token":"${JWT}"}`, "[REDACTED", JWT],
    ["OpenShift token", `login ok with ${OCP_TOKEN} (expires in 24h)`, "[REDACTED", OCP_TOKEN],
    ["AWS access key id", `using key ${AWS_KEY_ID} in us-east-1`, "[REDACTED:aws-access-key-id]", AWS_KEY_ID],
    ["GCP API key", `calling maps with ${GCP_KEY}`, "[REDACTED:gcp-api-key]", GCP_KEY],
    ["GCP OAuth token", `got ${j("ya", "29.", "a0AfH6SMBx1y2z3A4B5C6D7E8F9G0")} back`, "[REDACTED:gcp-oauth-token]", "a0AfH6SMBx1y2z3A4B5C6D7E8F9G0"],
    ["GitHub token", `pushing with ${GH_TOKEN}`, "[REDACTED:github-token]", GH_TOKEN],
    ["GitHub fine-grained token", `x ${j("github", "_pat_", "11ABCDEFG0abcdefghij_klmnopqrstuvwxyz0123456789")}`, "[REDACTED:github-token]", "11ABCDEFG0abcdefghij"],
    ["GitLab token", `${j("glp", "at-", "abcdefghijklmnopqrst")}`, "[REDACTED:gitlab-token]", "abcdefghijklmnopqrst"],
    ["Slack token", `slack ${SLACK}`, "[REDACTED:slack-token]", SLACK],
    ["Stripe key", `stripe ${STRIPE}`, "[REDACTED:stripe-key]", STRIPE],
    ["npm token", `${j("npm", "_", "abcdefghijklmnopqrstuvwxyz0123456789")}`, "[REDACTED:npm-token]", "abcdefghijklmnopqrstuvwxyz0123456789"],
    ["Vault token", `vault ${j("hv", "s.", "CAESIJabcdefghijklmnopqrstuvwxyz")}`, "[REDACTED:vault-token]", "CAESIJabcdefghijkl"],
    ["SendGrid key", `${j("SG", ".", "abcdefghijklmnop", ".", "qrstuvwxyz012345")}`, "[REDACTED:sendgrid-key]", "abcdefghijklmnop"],
  ])("%s", (_name, input, marker, secret) => {
    const out = redactLogText(input);
    expect(out).toContain(marker);
    gone(out, secret);
  });

  it("keeps the text around a token intact", () => {
    expect(redactLogText(`2030-01-01 INFO auth ok for ${AWS_KEY_ID}, region=us-east-1`)).toBe("2030-01-01 INFO auth ok for [REDACTED:aws-access-key-id], region=us-east-1");
  });
});

describe("redactLogText: PEM private keys", () => {
  const block = (kind = "") => [PEM_HEAD(kind), BODY1, BODY2, PEM_FOOT(kind)];

  it("replaces a multi-line key with one marker and keeps surrounding lines", () => {
    const out = redactLogText(["before", ...block(), "after"].join("\n"));
    expect(out).toBe("before\n[REDACTED PRIVATE KEY]\nafter");
    gone(out, BODY1, BODY2);
  });

  it.each(["RSA ", "EC ", "OPENSSH ", "ENCRYPTED ", "DSA ", "PGP "])("recognises the %sPRIVATE KEY variant", (kind) => {
    const out = redactLogText(block(kind).join("\n"));
    expect(out).toBe("[REDACTED PRIVATE KEY]");
  });

  it("keeps text before the header on the same line", () => {
    const out = redactLogText(`key dump: ${PEM_HEAD()}\n${BODY1}\n${PEM_FOOT()}`);
    expect(out).toBe("key dump: [REDACTED PRIVATE KEY]");
  });

  it("redacts an unterminated block to the end of the output (the tail may have cut the footer)", () => {
    const out = redactLogText(["ok", PEM_HEAD(), BODY1, BODY2, "still key material"].join("\n"));
    expect(out).toBe("ok\n[REDACTED PRIVATE KEY]");
  });

  it("redacts a block whose BEGIN line was cut off by tail (bare base64 lines before the footer)", () => {
    const out = redactLogText(["INFO started", BODY1, BODY2, PEM_FOOT(), "INFO next"].join("\n"));
    expect(out).toBe("INFO started\n[REDACTED PRIVATE KEY]\nINFO next");
    gone(out, BODY1, BODY2);
  });

  it("redacts a key serialised on one line with escaped newlines (JSON service-account files)", () => {
    const line = `{"type":"service_account","private_key":"${PEM_HEAD()}\\n${BODY1}\\n${BODY2}\\n${PEM_FOOT()}\\n","client_email":"sa@p.iam.example"}`;
    const out = redactLogText(line);
    gone(out, BODY1, BODY2);
    expect(out).toContain("client_email");
    expect(out).toContain("sa@p.iam.example");
  });

  it("handles several keys, and a key right after another", () => {
    const out = redactLogText([...block(), "between", ...block("RSA ")].join("\n"));
    expect(out).toBe("[REDACTED PRIVATE KEY]\nbetween\n[REDACTED PRIVATE KEY]");
  });

  it("does not touch certificates or public keys", () => {
    const cert = ["-----BEGIN CERTIFICATE-----", BODY1, "-----END CERTIFICATE-----", "-----BEGIN PUBLIC KEY-----", BODY2, "-----END PUBLIC KEY-----"].join("\n");
    expect(redactLogText(cert)).toBe(cert);
  });

  it("preserves CRLF line endings of untouched lines", () => {
    expect(redactLogText("a\r\nb\r\n")).toBe("a\r\nb\r\n");
    expect(redactLogText(`x\r\n${PEM_HEAD()}\r\n${BODY1}\r\n${PEM_FOOT()}\r\ny\r\n`)).toBe("x\r\n[REDACTED PRIVATE KEY]\r\ny\r\n");
  });
});

describe("redactLogText: ordinary text is left intact", () => {
  const SHA = "9fceb02d0ae598e95dc970b74767f19372d61af8";
  const UUID = "3f2b8c1e-9d4a-4b7e-8a1c-2f6d5e9b7a10";
  const DIGEST = `sha256:${"0123456789abcdef".repeat(4)}`;
  const lines = [
    "2030-05-01T10:00:00.123Z INFO  server listening on :8080 (pid 1)",
    `commit ${SHA} merged into main`,
    `request id ${UUID} completed in 12ms status=200`,
    `pulling image registry.example.com/shop/web@${DIGEST}`,
    "cache key=user:42:profile hit ratio=0.97",
    "Authorization header missing",
    "token_count=1532 max_tokens=4096 tokenizer=cl100k token.expires=5 tokens: 12",
    "started with --password-file /etc/pw --token-ttl 5m",
    "msg_sig=abc unsig=def foosig: x",
    "secretName: db-credentials",
    "Secret \"db-credentials\" created in namespace shop",
    "MountVolume.SetUp failed for volume \"creds\" : secret \"db-credentials\" not found",
    "password policy: 12 characters minimum",
    "invalid password for user bob",
    "passwordless login enabled",
    "PWD=/home/app SHELL=/bin/sh",
    "bearer authentication is not enabled",
    "design=blue assign=1 sign=2 signature mismatch",
    `data: ${Buffer.from("this is not a secret, just some base64 text").toString("base64")}`,
    `etag "${Buffer.from("0123456789abcdef0123").toString("base64")}"`,
    "Traceback (most recent call last):",
    '  File "/app/main.py", line 42, in handler',
    "    raise ValueError(\"bad input\")",
    "ValueError: bad input",
    "java.lang.NullPointerException: Cannot invoke \"String.length()\" because \"s\" is null",
    "\tat com.example.shop.Checkout.pay(Checkout.java:87)",
    "\tat com.example.shop.Main.main(Main.java:12)",
    "goroutine 1 [running]:",
    "main.main()\n\t/app/main.go:25 +0x1d",
    "panic: runtime error: index out of range [5] with length 3",
    "password=",
    "password: null",
    "token: ${TOKEN}",
    "password=$DB_PASSWORD",
    "secret=<none>",
    "https://example.com/a/b?c=d#frag",
    "",
    "   ",
  ];
  it.each(lines)("unchanged: %j", (l) => {
    expect(redactLogText(l)).toBe(l);
  });

  it("returns a realistic log unchanged, byte for byte", () => {
    const log = lines.join("\n") + "\n";
    expect(redactLogText(log)).toBe(log);
  });

  it("passes empty input through", () => {
    expect(redactLogText("")).toBe("");
  });
});

describe("redactLogText: documented trade-offs", () => {
  it("masks the value of any secret-named key, even when it is only a reference name", () => {
    expect(redactLogText("imagePullSecret: regcred")).toBe(M("imagePullSecret: <M>"));
  });

  it("does NOT catch a bare secret with no known shape and no telling key", () => {
    expect(redactLogText(`the value is ${AWS_SECRET}`)).toContain(AWS_SECRET);
    expect(redactLogText("user typed hunter2hunter2 into the form")).toContain("hunter2hunter2");
  });

  it("ends an unquoted value at whitespace, comma, semicolon, ampersand or a quote", () => {
    expect(redactLogText("password=ab,cd")).toBe(M("password=<M>,cd"));
  });
});

describe("redactLogText: idempotent and total", () => {
  const samples = [
    `password=hunter2hunter2 ${JWT} ${AWS_KEY_ID} Authorization: Bearer abc123DEF456ghi789 postgres://u:pw1pw1pw@h/db`,
    [PEM_HEAD(), BODY1, PEM_FOOT()].join("\n"),
    '{"password":"x1y2z3w4","a":[1,2,3]}',
  ];
  it.each(samples)("redacting twice equals redacting once: %#", (s) => {
    const once = redactLogText(s);
    expect(redactLogText(once)).toBe(once);
  });

  it("never throws on odd input", () => {
    for (const s of ["\u0000\u0001", "\\", '"', "\\\"", "password", "password=", "password=\"", 'password=\\"', "Bearer", "://", "@:@://", "-----BEGIN ", PEM_HEAD(), PEM_FOOT(), "😀password=😀", "\n\n\n"])
      expect(() => redactLogText(s)).not.toThrow();
  });
});

describe("redactLogText: seeded fuzz", () => {
  const pieces = ["password", "token", "=", ":", '"', "'", " ", "\\", "Bearer ", "eyJ", "-----BEGIN ", "PRIVATE KEY-----", "-----END ", "://", "@", "a", "\n", "\r", "AKIA", "sig", "<M>", "--", "secret_key", "Authorization", ".", "-", "[", "]", "sha256~", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijkl"];
  it("never throws and is idempotent on 300 random inputs", () => {
    for (let seed = 1; seed <= 300; seed++) {
      let r = seed * 7919;
      const rnd = () => (r = (r * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
      let s = "";
      for (let n = 50 + Math.floor(rnd() * 400); n > 0; n--) s += pieces[Math.floor(rnd() * pieces.length)];
      const once = redactLogText(s);
      expect(redactLogText(once), JSON.stringify(s)).toBe(once);
    }
  });
});

describe("redactLogText: pathological input stays fast (linear, no catastrophic backtracking)", () => {
  const MB = 1024 * 1024;
  const fill = (unit: string) => unit.repeat(Math.ceil(MB / unit.length)).slice(0, MB);
  const cases: Array<[string, string]> = [
    ["one letter", fill("a")],
    ["spaces", fill(" ")],
    ["keyword run", fill("password")],
    ["keyword=run", fill("password=")],
    ["keyword: run", fill("token: ")],
    ["quoted run", fill('secret="')],
    ["unterminated quote after key", `password="${fill("x")}`],
    ["JWT prefix run", fill("eyJ")],
    ["JWT prefix then token chars", `eyJ${fill("a")}`],
    ["JWT with dots", `eyJ${fill("aaaaa.")}`],
    ["bearer run", fill("Bearer ")],
    ["bearer then spaces", `Bearer${fill(" ")}`],
    ["bearer then long token", `Bearer ${fill("a1")}`],
    ["authorization scheme run", fill("Authorization: Basic ")],
    ["url scheme run", fill("://")],
    ["url with long authority", `http://${fill("a")}`],
    ["url with colon/at run", fill("http://a:b@")],
    ["colon-at-slash run", fill(":@/")],
    ["PEM header run", fill("-----BEGIN ")],
    ["PEM header words", `-----BEGIN ${fill("A ")}`],
    ["PEM header+footer run", fill(`${PEM_HEAD()}${PEM_FOOT()}`)],
    ["PEM footer run", fill(PEM_FOOT())],
    ["base64 lines then footer", `${fill(`${BODY1}\n`)}${PEM_FOOT()}`],
    ["token chars with dots and equals", fill("a.b=c/")],
    ["AWS prefix run", fill("AKIA")],
    ["backslash run", fill("\\")],
    ["escaped-quote run", fill('\\"')],
    ["sig run", fill("sig=")],
    ["many short lines", fill("password=abc\n")],
    ["many empty lines", fill("\n")],
  ];
  it.each(cases)("1 MB: %s", (_name, input) => {
    expect(input.length).toBeGreaterThanOrEqual(MB);
    const t0 = performance.now();
    const out = redactLogText(input);
    const ms = performance.now() - t0;
    expect(typeof out).toBe("string");
    expect(ms).toBeLessThan(1500);
  }, 20_000);
});
