# SSO (OIDC) issuer setup

ntwire-server never becomes a confidential OAuth client: it verifies ID
tokens the *client* obtained against the issuer's published JWKS, and never
authenticates itself to the IdP with a secret it protects. Register ntwire
as a **public** client with the IdP, using PKCE and (optionally) the device
flow — never a "web application" / confidential client type, which expects
a secret used to actually authenticate the server as a client.

Some IdPs (Google's "Desktop app" client type, notably) still require a
`client_secret` value on token-endpoint requests even for this public/PKCE
registration — see the Google section below. Never put that value in
`auth.oidc.issuers`: `/v1/info` is public. Set it locally in the client
environment as `NTWIRE_OIDC_CLIENT_SECRET` instead.

The redirect used by the browser flow is a loopback address chosen at login
time (`http://127.0.0.1:<random-port>/callback`); register the broadest
loopback pattern the IdP allows rather than a fixed port, since ntwire binds
an ephemeral port for each login.

## Google

1. Console: **APIs & Services → Credentials → Create Credentials → OAuth
   client ID**.
2. Application type: **Desktop app** (this is Google's public-client type
   and permits loopback redirects). Note the generated **Client ID** *and*
   **Client Secret** — unlike most public/PKCE clients, Google's token
   endpoint rejects the authorization-code exchange with
   `invalid_request: client_secret is missing` for this client type if the
   secret isn't sent, even though PKCE is used and Google itself doesn't
   treat this value as confidential (its docs explicitly say it can ship in
   installed-app source). Only Google's Android/iOS/Chrome-app client types
   are exempt from this; Desktop app is not.
3. Under **OAuth consent screen**, add the scopes `openid`, `email`,
   `profile`.
4. Server config (without a secret):
   ```yaml
   auth:
     oidc:
       issuers:
         - name: google
           issuer: https://accounts.google.com
           client_id: "<client-id>.apps.googleusercontent.com"
           scopes: [openid, email, profile]
   ```
   Before running the client, set `NTWIRE_OIDC_CLIENT_SECRET` to the generated
   secret in that client's environment. Do not add it to the server config.
   Google does not advertise `offline_access` in its scope list; ntwire
   detects this and requests a refresh token via `access_type=offline`
   automatically — no extra configuration needed.
5. Google's device flow requires the **TV and Limited Input devices** client
   type instead of Desktop app if you need `--no-browser` support; otherwise
   `ntwire connect --sso` (browser flow) works with the Desktop app client
   above.

**Troubleshooting:** if `--sso` fails with
`start device authorization: oauth2: "invalid_client" "Invalid client type."`
even without `--no-browser`, that's usually not about the device flow at
all — the browser (PKCE) attempt failed first for an unrelated reason (most
often the missing `client_secret` above) and ntwire silently fell back to
the device flow, which then fails on its own, separate client-type
restriction. Check the actual PKCE failure before chasing the device-flow
error.

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
