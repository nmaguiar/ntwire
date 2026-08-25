# ntwire Portal

The **ntwire Portal** is an administrator-configurable, identity-aware resource portal that presents connecting users with the internal services they are authorized to access.

It supports two distinct deployment and access modes:

1. **Native ntwire Client Portal**
   * Accessible via the native client status dashboard (`http://127.0.0.1:<port>/?token=...`) under the **Portal** tab.
   * Supports rich interactive actions, such as launching Chrome/Chromium in an isolated browser profile (`ntwire://open/<target_id>`) with automated SOCKS proxying.
   * Real-time local connection status and clipboard copying for service credentials or CLI commands.

2. **WireGuard Web Portal**
   * An in-tunnel HTTP server listening directly on an overlay IP (e.g. `100.64.0.1:8080`) over WireGuard.
   * Accessible from any browser running on standard WireGuard clients (iOS, Android, macOS, Linux, Windows) without requiring the ntwire native client binary.
   * Maps client tunnel IP address to authenticated identity (via session or native WireGuard peer table) to render only authorized targets.
   * Protected with strict security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options) and HTML sanitization.

---

## 1. Security & Architecture Model

### Declarative Untrusted Content
Portal templates are treated as **untrusted declarative content**. Even if a portal template is authored by an external party or an LLM:
* The template engine has no access to system execution, filesystem APIs, or unrestricted language runtime functions.
* The template cannot discover, inspect, or reveal unauthorized targets or sensitive network metadata.
* Rendering occurs **exclusively** against an already-filtered, authorized target set for the specific principal.
* If a user is not granted access to a target, that target and its containing category (if empty) are completely omitted from the context, the Markdown, and the rendered HTML.

### Action Authorization Enforcement
Actions (such as `ntwire://open/<target_id>`) do not accept arbitrary URLs or arbitrary connect commands. The server and client re-verify target authorization upon action dispatch. For a browser launch, the URL is resolved from the authorized target's `portal.url`; the local client action endpoint rejects caller-supplied URL fields. If a user triggers an action for an unauthorized target ID, it is rejected with `403 Forbidden` and audited.

### Fail-Closed Identity Resolution
For the WireGuard web portal:
* The client's source IP address within the overlay network (`r.RemoteAddr`) is resolved to a verified session or native WireGuard peer identity.
* If the source IP cannot be verified, the request is immediately rejected with `403 Forbidden` without evaluating or rendering any portal content.

---

## 2. Server Configuration

Add a `portal:` block to your `ntwire.yaml` configuration:

```yaml
portal:
  enabled: true
  title: "Engineering Portal"
  template: "portal.md"             # Path to template file or inline markdown
  variables:
    environment: "Production"
    support_channel: "#help-infra"
  web:
    enabled: true
    listen: "100.64.0.1:8080"        # In-tunnel listener address

tunnels:
  - name: egress
    target: socks
    virtual_port: 1080
    local_port: 1080
    socks:
      filters:
        - "10.0.0.0/8"
    portal:
      name: "Corporate SOCKS Egress"
      description: "SOCKS5 egress proxy for internal network access"
      category: "Network"
      icon: "network"

  - name: grafana
    target: grafana.internal:3000
    virtual_port: 3000
    local_port: 3000
    portal:
      name: "Grafana Dashboards"
      description: "Metrics and observability dashboards"
      category: "Observability"
      icon: "chart"
      url: "http://grafana.internal:3000"
      applications:
        - "grafana"
        - "prometheus"

  - name: postgres
    target: pgsql.internal:5432
    virtual_port: 5432
    local_port: 5432
    instructions: |
      Connect with psql:
      ```bash
      psql -h {{.LocalHost}} -p {{.LocalPort}} -U appuser mydb
      ```
    portal:
      name: "Customer Database"
      description: "PostgreSQL read replica"
      category: "Databases"
      icon: "database"
```

---

## 3. Template Authoring

Portal templates use standard Markdown augmented with a safe, restricted placeholder and conditional syntax.

### Available Variables

* `{{portal.title}}` — Configured portal title.
* `{{user.identity}}` — Authenticated username or key fingerprint.
* `{{user.display_name}}` — User display name or email.
* `{{variables.<NAME>}}` (or `{{<NAME>}}`) — Custom variables defined in `portal.variables`.

### Capabilities & Conditionals

Use capabilities to adapt the presentation depending on whether the client is a native ntwire client or a standard WireGuard web browser:

```markdown
{{#if capability.open_socks_browser}}
[Open in Isolated Browser](ntwire://open/{{id}})
{{/if}}

{{#if capability.web_portal}}
[Open Web Service]({{url}})
{{/if}}

{{#if target.postgres}}
> Note: PostgreSQL access requires your team SSH certificate.
{{/if}}
```

### Iteration

Loop over authorized categories and targets:

```markdown
{{#each categories}}
## {{name}}

{{#each targets}}
### {{name}}
{{description}}

{{#if url}}
{{#if capability.open_socks_browser}}
[Open in Browser](ntwire://open/{{id}})
{{/if}}
{{#if capability.web_portal}}
[Open Web Service]({{url}})
{{/if}}
{{/if}}

{{#if connection_instructions}}
{{connection_instructions}}
{{/if}}

{{/each}}
{{/each}}
```

---

## 4. CLI Tooling & LLM Generation

`ntwire-server portal` provides built-in tooling for describing, validating, authoring, and rendering portal templates.

### `portal describe`
Prints the machine-readable JSON descriptor (`ntwire.portal/v1`) of the portal schema and available targets without exposing secrets:

```bash
ntwire-server portal describe -config ntwire.yaml
```

### `portal prompt`
Generates a sanitized prompt that can be pasted into any LLM (or supplied to an autonomous assistant) to generate a tailored `portal.md`:

```bash
ntwire-server portal prompt -config ntwire.yaml > prompt.txt
```

### `portal validate`
Statically validates a template for syntax correctness, prohibited `<script>` tags, dangerous URI schemes, and unknown target IDs:

```bash
ntwire-server portal validate -config ntwire.yaml -template portal.md
```

### `portal render`
Renders the portal against configured targets for testing and preview:

```bash
# Render to Markdown
ntwire-server portal render -config ntwire.yaml -format markdown

# Render to styled HTML page
ntwire-server portal render -config ntwire.yaml -format full-html > portal.html

# Render in WireGuard web mode
ntwire-server portal render -config ntwire.yaml -mode wireguard -format full-html
```

---

## 5. Control Plane Protocol Endpoints

The server exposes the following HTTP endpoints on its HTTPS control plane:

### `GET /v1/portal?mode=native`
* **Headers**: `Authorization: Bearer <session-token>`
* **Response**: `200 OK`
  ```json
  {
    "title": "Engineering Portal",
    "markdown": "# Engineering Portal...",
    "html": "<h1>Engineering Portal</h1>...",
    "context": {
      "schema": "ntwire.portal/v1",
      "portal": {"title": "Engineering Portal"},
      "user": {"identity": "alice", "display_name": "alice"},
      "targets": [...]
    }
  }
  ```

### `POST /v1/portal/action`
* **Headers**: `Authorization: Bearer <session-token>`
* **Request**:
  ```json
  {
    "action": "open",
    "target_id": "grafana"
  }
  ```
* **Response**: `200 OK` (with action resolution details) or `403 Forbidden` (if target is unauthorized).
