# SSO (OIDC) issuer setup

ntwire-server never becomes a confidential OAuth client: it holds no client
secret and only verifies ID tokens the *client* obtained, against the
issuer's published JWKS. Register ntwire as a **public** client with the IdP,
using PKCE and (optionally) the device flow — never a "web application" /
confidential client type, which would expect a secret ntwire never sends.

The redirect used by the browser flow is a loopback address chosen at login
time (`http://127.0.0.1:<random-port>/callback`); register the broadest
loopback pattern the IdP allows rather than a fixed port, since ntwire binds
an ephemeral port for each login.

## Google

1. Console: **APIs & Services → Credentials → Create Credentials → OAuth
   client ID**.
2. Application type: **Desktop app** (this is Google's public-client type; it
   requires no secret and permits loopback redirects). Note the generated
   **Client ID** — there is no secret to record.
3. Under **OAuth consent screen**, add the scopes `openid`, `email`,
   `profile`.
4. Server config:
   ```yaml
   auth:
     oidc:
       issuers:
         - name: google
           issuer: https://accounts.google.com
           client_id: "<client-id>.apps.googleusercontent.com"
           scopes: [openid, email, profile]
   ```
   Google does not advertise `offline_access` in its scope list; ntwire
   detects this and requests a refresh token via `access_type=offline`
   automatically — no extra configuration needed.
5. Google's device flow requires the **TV and Limited Input devices** client
   type instead of Desktop app if you need `--no-browser` support; otherwise
   `ntwire connect --sso` (browser flow) works with the Desktop app client
   above.

## Microsoft Entra ID (Azure AD)

1. Portal: **Microsoft Entra ID → App registrations → New registration**.
2. Supported account types: pick per your tenant (single-tenant is typical
   for internal use).
3. Redirect URI: platform **Mobile and desktop applications**, and add
   `http://localhost` — Entra treats this as a loopback wildcard covering any
   ephemeral port ntwire binds. Do not use the **Web** platform type (that
   implies a confidential client).
4. Under **Authentication**, enable **Allow public client flows** — this is
   required for both PKCE without a secret and the device code flow.
5. Under **API permissions**, ensure `openid`, `email`, `profile`, and
   `offline_access` (delegated, Microsoft Graph) are present; Entra grants
   `offline_access` by default for public clients but confirm it is not
   removed.
6. Note the **Application (client) ID** and the **Directory (tenant) ID**.
7. Server config:
   ```yaml
   auth:
     oidc:
       issuers:
         - name: entra
           issuer: https://login.microsoftonline.com/<tenant-id>/v2.0
           client_id: "<application-client-id>"
           scopes: [openid, email, profile]
           groups_claim: groups   # only if group claims are configured below
   ```
8. For `group:` grants, configure the app registration's **Token
   configuration** to emit a `groups` claim (group IDs or, for smaller
   directories, group names via the "Groups assigned to the application"
   option), matching `groups_claim` above.

## Keycloak / other generic OIDC providers

Any provider exposing standard OIDC discovery
(`<issuer>/.well-known/openid-configuration`) works without provider-specific
code. Register a **public** client (no client authentication / no secret),
enable the **Standard flow** (authorization code + PKCE) and, if needed,
**OAuth 2.0 Device Authorization Grant**, and set a loopback redirect URI
pattern such as `http://127.0.0.1:*` if the provider supports wildcards, or
the broadest loopback prefix it allows otherwise.
