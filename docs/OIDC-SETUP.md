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

## Keycloak

The following uses the Keycloak Admin Console. It registers ntwire as a public
desktop client; the ntwire server verifies issued ID tokens but never uses a
Keycloak client secret.

1. Create or select the realm that owns the ntwire users. Require users to
   have an email address. With ntwire's default `require_verified_email:
   true`, enable email verification and have existing users verify their
   addresses. Their ID tokens must contain both `email` and
   `email_verified: true`.
2. Go to **Clients → Create client**. Set the client type to **OpenID
   Connect**, choose a client ID such as `ntwire`, and continue.
3. In **Capability config**, enable **Standard flow**. Leave **Client
   authentication** off: this makes it a public client and avoids a client
   secret. Enable **OAuth 2.0 Device Authorization Grant** only if operators
   need `ntwire connect --sso --no-browser`.
4. In **Login settings**, add `http://127.0.0.1:*` under **Valid redirect
   URIs**. ntwire opens `http://127.0.0.1:<random-port>/callback` for every
   browser login, so the wildcard port is necessary. Do not use a broad
   non-loopback wildcard. Set **Web origins** to the default/empty setting;
   ntwire is not a browser application served from an origin.
5. In **Client scopes**, ensure the client receives `openid`, `email`, and
   `profile`. The default Keycloak scopes normally supply these claims. If
   they were customized, add an email mapper that includes the email and
   verified-email claims in the **ID token**.
6. If ntwire will use `group:` grants, create or attach a client scope with a
   **Group Membership** mapper. Set its token claim name to `groups`, turn on
   **Add to ID token**, and use the same name in `groups_claim` below. Assign
   users to the corresponding realm or client groups.
7. Save the client and put its client ID and the realm's exact issuer URL in
   the server configuration. The issuer is normally
   `https://<keycloak-host>/realms/<realm>`; use the value of Keycloak's
   discovery document `issuer` field rather than an admin-console URL.

```yaml
auth:
  oidc:
    issuers:
      - name: keycloak
        issuer: https://sso.example.com/realms/engineering
        client_id: ntwire
        scopes: [openid, email, profile]
        groups_claim: groups # omit when group: grants are not used
```

Restrict access in `grants` with exact verified emails or explicit groups,
then reload the server and connect with `ntwire connect --sso --provider
keycloak`. Never add a Keycloak client secret to this YAML; ntwire rejects it
because the issuer list is returned in public server metadata.

## Amazon Cognito user pools

Amazon Cognito User Pools issues standards-compliant OIDC ID tokens, but it
cannot currently complete ntwire's desktop login flow. Cognito requires every
callback URL to be pre-registered and exact (and only permits HTTP for
`localhost` in its local-development exception). ntwire deliberately uses an
ephemeral `http://127.0.0.1:<random-port>/callback` redirect. Cognito has no
wildcard callback-port registration for that redirect, and it does not expose
an OAuth device-authorization grant as an alternative.

Do not add a Cognito issuer to `auth.oidc.issuers` expecting the current CLI
or GUI to work: authorization will fail at Cognito's callback-URL validation.
A fixed redirect URI / callback configuration in ntwire is required before a
Cognito setup can be supported safely. A redirect proxy is not a workaround,
because the redirect URI used when redeeming an authorization code must match
the one used for authorization.

When ntwire supports a registered fixed loopback redirect, configure Cognito
as follows:

1. Create a **User Pool**, require an email address, and enable email
   verification. ntwire's default policy requires `email_verified: true` in
   the ID token.
2. Add a **User Pool domain** (Cognito-hosted or custom). The domain enables
   Cognito's OAuth/OIDC authorization and token endpoints.
3. Create an **app client** of type **Public client** with no generated client
   secret. Enable only the **Authorization code grant** and PKCE; do not
   enable implicit or client-credentials grants for ntwire.
4. Register the fixed redirect URI that a future ntwire release documents,
   and allow the `openid`, `email`, and `profile` scopes. The `email` scope is
   required for the `email` and `email_verified` ID-token claims.
5. Use the user-pool issuer, not the hosted-login domain, in server config:
   `https://cognito-idp.<aws-region>.amazonaws.com/<user-pool-id>`. For
   `group:` grants, set `groups_claim: cognito:groups`; Cognito places user
   pool group membership in that ID-token claim.

The eventual server entry will have this form (but must wait for the fixed
redirect support described above):

```yaml
auth:
  oidc:
    issuers:
      - name: cognito
        issuer: https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_example
        client_id: <public-app-client-id>
        scopes: [openid, email, profile]
        groups_claim: cognito:groups # omit when group: grants are not used
```

## Other generic OIDC providers

Any standards-compliant OIDC provider can work if it supports ntwire's
ephemeral loopback callback URI (`http://127.0.0.1:<random-port>/callback`),
normally by allowing a loopback wildcard port. Register a **public** client
(no client authentication / no secret), enable authorization code + PKCE and,
if required, OAuth 2.0 Device Authorization Grant. `--no-browser` (or a host
without a browser) uses the device flow, which prints a URL and code to enter
on another device.
