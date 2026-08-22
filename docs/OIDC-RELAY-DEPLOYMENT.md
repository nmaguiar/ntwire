---
title: OIDC deployment over HTTPS and relay
description: Secure end-to-end deployment of ntwire SSO with direct and relayed servers
type: guide
---

# OIDC deployment over HTTPS and relay

This guide deploys `ntwire-server` with Google, Microsoft Entra ID,
Keycloak, or another standards-compliant OpenID Connect (OIDC) provider. It
works the same when the server is reached directly or through `ntwire-relay`.

The client, not `ntwire-server`, is the OAuth public client. It uses
Authorization Code + PKCE in a browser, and can use the device flow where the
provider enables it. The server verifies the returned ID token against the
configured issuer's discovery document and JWKS, then creates an ntwire
session. Do not register ntwire as a confidential web application or give the
server a confidential OAuth client secret.

## 1. Establish HTTPS identity

Choose the hostname clients will use:

- Direct server: `ntwire.example.com`.
- Relay tenant: `home.relay.example.com`; the relay domain needs wildcard DNS
  and the origin server certificate must be valid for this hostname.

Use a CA-issued certificate for a long-lived deployment and protect its
private key on the origin `ntwire-server`. A self-signed certificate with a
managed, out-of-band client pin is appropriate only when operating a private
deployment. Never use `ntwire connect --insecure` outside a disposable
environment.

```yaml
tls:
  cert_file: /etc/ntwire/tls/fullchain.pem
  key_file: /etc/ntwire/tls/privkey.pem
```

The relay does not receive this private key. It reads the TLS ClientHello only
to select the tenant, then forwards the encrypted bytes to the origin.

## 2. Register a public OIDC client

Register a separate public/native OAuth client for ntwire at each chosen IdP.
Use a loopback redirect supported by that IdP because the client chooses an
ephemeral local port at login time. Request `openid`, `email`, and `profile`;
also enable refresh-token/device-code support if users need non-browser login.

- **Google:** create a Desktop app client. Google's Desktop token endpoint
  requires the generated client secret, but treat it as public client
  metadata rather than a protected secret: it goes only in each client's
  `NTWIRE_OIDC_CLIENT_SECRET` environment variable, never in the server's
  `auth.oidc.issuers` configuration below — the server rejects a
  `client_secret` field there at startup (see [OIDC-SETUP.md](OIDC-SETUP.md)).
- **Microsoft Entra ID:** create a Mobile and desktop application redirect for
  `http://localhost`, enable public client flows, and choose the intended
  tenant in the issuer URL.
- **Keycloak and other providers:** create a public client, enable standard
  flow with PKCE, and enable the device authorization grant when required.

See [OIDC-SETUP.md](OIDC-SETUP.md) for provider-console steps and constraints.

## 3. Configure identity verification and authorization

Configure the exact issuer URL and its public client ID. The server discovers
the provider's endpoints and signing keys; it accepts an ID token only when
its signature, expiry, audience, and verified-email requirement pass.

```yaml
auth:
  session_ttl: 15m
  max_sessions_per_key: 5
  oidc:
    issuers:
      - name: entra
        issuer: https://login.microsoftonline.com/<tenant-id>/v2.0
        client_id: <public-client-id>
        scopes: [openid, email, profile]
        groups_claim: groups
        require_verified_email: true
tunnels:
  - name: reports
    target: reports.internal:8080
    virtual_port: 18080
    allow:
      - "group:engineering"
      - "alice@example.com"
```

Prefer specific `group:` grants (with the IdP configured to emit that claim)
or exact emails. A domain grant such as `@example.com` authorizes every
verified identity in that domain. An optional `authorizer` hook can deny a
login or narrow grants, but it cannot expand the YAML grants; do not make
relay-supplied source IP an authorization input.

## 4. Add relay transport when the server has no inbound reachability

The relay registration key is independent from client SSH keys and OIDC
identities. Register that key under the intended tenant at the relay, point
wildcard DNS at its public TCP listener, and configure the origin server to
dial the relay over authenticated TLS:

```yaml
relay:
  enabled: true
  url: wss://relay.example.com:8444
  name: home
  identity_file: /etc/ntwire/relay_id_ed25519
  fingerprint: "SHA256:<relay-agents-certificate-pin>"
network:
  advertised_endpoint: ""
```

Clients then use the normal client command against the tenant hostname:

```sh
ntwire connect --sso --provider entra https://home.relay.example.com
```

The client-to-origin TLS session, including `POST /v1/auth/oidc`, remains
end-to-end. The relay cannot read or modify the ID token, ntwire bearer token,
or WireGuard traffic. It is still an availability dependency and its reported
client source IP is suitable for rate limiting and audit context only, not an
authorization boundary. Leave `relay.advertise_direct` disabled when clients
must not learn the origin server's public UDP address.

## 5. Validate and operate

Before granting production access, test each provider through both browser
PKCE and device flow where enabled. Verify rejection of an expired token, a
token for another client ID, an unverified email, and an identity outside the
configured grants. Repeat a successful SSO connection via the relay hostname
and verify certificate pinning, audit events, and WebSocket fallback.

Keep sessions short, review the per-identity session cap, and revoke active
sessions through the protected admin endpoint when immediate removal is
needed. Provider-side deprovisioning is not instantaneous for an existing
ntwire session; the effective bound is the session TTL unless the session is
revoked or a configuration reload removes its grant.

For protocol details, see [PROTOCOL.md](PROTOCOL.md#oidc-authentication-request),
[RELAY.md](RELAY.md), and [SECURITY.md](SECURITY.md#the-relays-trust-model).
