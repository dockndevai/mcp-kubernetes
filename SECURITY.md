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
  Add more via `K8S_PROTECTED_NAMESPACES`. The namespace checked is the one a call really acts on: for a
  `Namespace` that is its own name (in `delete_resource`, `get_resource` and `apply_manifest`), and for a
  namespaced kind with no namespace given it is the kube-config context's default namespace.
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
- `get_resource` redacts Secret values before they reach the model: `data` and `stringData` values become
  `<redacted, N bytes>` (keys are kept) and the `kubectl.kubernetes.io/last-applied-configuration` annotation,
  which holds a copy of the values, is redacted. No other tool reads Secret objects. This is not optional.
- **Credentials in objects are redacted, best effort (`K8S_REDACT_OBJECTS`).** `get_pod`, `get_resource`, the
  `message` of `list_events` and the text of API error responses can carry credentials that are not in a Secret.
  Secrets themselves are **always** redacted (above, also when nested in a List); the rest is heuristic, on by default,
  and `K8S_REDACT_OBJECTS=false` (or `0`, `no`, `off`; any other value, including a typo, leaves it on) returns those
  objects unchanged. What it masks:
  - `env` entries (containers, initContainers, ephemeralContainers, and every pod template: Deployments, StatefulSets,
    DaemonSets, ReplicaSets, Jobs, CronJobs' `jobTemplate`, custom resources, ...), probe `httpHeaders` and `parameters`
    lists: the `value` of an entry whose **name** ends in a secret-ish word (the same list as the log redactor, plus
    `key`, `auth`, `pass`, `pwd`, `dsn`, `jwt`, `bearer`, `connection_string`; case-insensitive, `_`/`-` optional,
    so `DB_PASSWORD`, `apiKey`, `SENTRY_DSN`, `AZURE_STORAGE_CONNECTION_STRING`) becomes `<redacted, N bytes>`. Every other
    value is still scrubbed for URL passwords, token shapes, `key=value` pairs and PEM private keys.
    `valueFrom` references are kept: a `secretKeyRef` names a Secret and does not hold the value.
  - `command` and `args`: each element is scrubbed (`--db-password=x`), and the element after a secret-named flag
    (`--password x`) is masked.
  - ConfigMap `data` and `binaryData`: an entry whose **key** is secret-shaped (`db.password`, `tls.key`,
    `credentials.json`, `id_rsa`, `*.p12`/`*.jks`, `.dockerconfigjson`) is masked; any other text value is scrubbed
    like a log (so one `client_secret=...` line in a properties file is masked and the rest stays readable); a
    `binaryData` entry is decoded and masked as a whole when the text inside holds a credential.
  - OpenShift `Route` `tls.key` / `spec.tls.key` is masked; `certificate`, `caCertificate` and
    `destinationCACertificate` are public by design and stay readable, except that a private key pasted into one is masked.
  - `BuildConfig` webhook trigger secrets; `Event` messages; passwords in any `scheme://user:password@host` URL in any
    string (for example a git URL).
  - The `kubectl.kubernetes.io/last-applied-configuration` annotation, which holds a copy of the manifest including
    env values, is parsed and redacted the same way (replaced by `<redacted>` if it is not JSON).
  This is **heuristic and mostly by name**. It does **not** catch a credential stored under an innocuous name with an
  innocuous shape (`CONFIG=<random string>`), a password written in a ConfigMap file that is not `key=value`,
  `key: value` or `"key":"value"` shaped, an opaque binary blob under a neutral name (a keystore called `blob.bin`),
  or a credential in a field this list does not name (an annotation other than last-applied, a CRD field). It
  over-redacts on purpose: a variable such as `GOOGLE_APPLICATION_CREDENTIALS` (a path) or `SMTP_AUTH` is masked.
  Responses are normalised to plain JSON (as they are sent to the model anyway), and nesting deeper than 64 levels
  is replaced by a marker rather than inspected. `apply_manifest`, `delete_resource` and `scale_deployment` return only
  the object's identity (`kind`, `name`, `namespace`, ...), never its content, and `list_pods` / `list_deployments` /
  `list_services` / `list_nodes` return fixed summaries without env, so none of them needs this pass.
- **Log output is redacted, best effort.** Output from `get_pod_logs` and from `exec_in_pod` (stdout and stderr) is scanned, and credential-shaped text is masked before it reaches the model.
  This is **heuristic defence in depth, not a guarantee**: it cannot know what a workload considers secret. It is on
  by default; `K8S_REDACT_LOGS=false` (or `0`, `no`, `off`) turns it off (any other value, including a typo, leaves it on). What it masks
  (each as `[REDACTED]`, `[REDACTED:<kind>]` or `[REDACTED PRIVATE KEY]`, with the rest of the line kept):
  - PEM private-key blocks (RSA, EC, OpenSSH, encrypted, PGP, plain `PRIVATE KEY`), including a block that is
    unterminated or whose `BEGIN` line was cut off by `tail` (its bare base64 body lines are dropped);
    certificates and public keys are left alone.
  - The value of any `key=value`, `key: value`, `"key":"value"` or `--flag value` whose key **ends in**
    `password`, `passwd`, `passphrase`, `secret`, `token`, `credential(s)`, `authorization`, `api_key`, `access_key`,
    `secret_key`, `secret_access_key`, `private_key`, `signing_key`, `encryption_key`, `master_key`, `account_key`, `auth_key`,
    `primary_key`, `secondary_key` (case-insensitive, `_`/`-` optional), plus `X-Amz-Signature` and `sig`. For
    `Authorization:` the scheme (`Bearer`, `Basic`, ...) is kept and the credential after it is masked.
  - `Bearer <token>` anywhere (the token must contain a digit, so prose like "bearer authentication" is untouched).
  - The password in `scheme://user:PASSWORD@host` URLs (database and registry DSNs, `https://x-access-token:...@github.com`).
  - Well-known token shapes, with no key name needed: JWTs (which includes Kubernetes service-account tokens), OpenShift
    `sha256~` tokens, AWS access key ids, GCP API keys and OAuth tokens, GitHub, GitLab, Slack, Stripe, npm, Vault and
    SendGrid tokens.
  What it does **not** catch: a secret with no recognisable shape and no telling key name (a bare random password, a
  raw AWS secret access key on its own, a password in a sentence), secrets split across lines (other than PEM
  blocks), encoded or obfuscated secrets, cookies and session ids, scheme-less `user:pass@host` DSNs, and personal data.
  Deliberate trade-offs: the value after a secret-named key is masked even when it is only a reference name
  (`imagePullSecret: regcred`); an unquoted value ends at whitespace, a comma, `;`, `&`, `<`, `>` or a quote, so a password
  containing one of those is only partly masked; and `null`/`true`/`none`-style words, `$VAR` references and
  already-redacted markers are left as they are. The pass is line oriented and linear in the output size (no
  backtracking-prone patterns; a 1 MB single line is covered by a test). With `K8S_REDACT_LOGS=false` both are returned exactly as the workload produced them.
- `exec_in_pod` is powerful (arbitrary in-container commands). Enable it only for
  trusted, tightly-scoped clusters.

## Reporting a vulnerability

Please open a private security advisory on the GitHub repository rather than a
public issue.
