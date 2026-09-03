---
title: Let's Encrypt certificates
description: Obtaining and renewing a CA-trusted certificate for ntwire-server alone, and for a server registered behind ntwire-relay
type: guide
---

# Let's Encrypt certificates

By default `ntwire-server` (and `ntwire-relay`'s `listen.agents`) generate
and persist a self-signed certificate. That is enough for the `ntwire`
CLI/GUI client, which pins the certificate by SHA-256 fingerprint on first
connect regardless of hostname (TOFU — see
[SECURITY.md#tls-trust-model-and-avoiding-repeated-re-trust-prompts](SECURITY.md#tls-trust-model-and-avoiding-repeated-re-trust-prompts)).

It is **not** enough for anything that does ordinary system certificate
validation instead: a browser, `relay.direct_clients` traffic hitting a plain
hostname, or an OS proxy auto-config fetch such as iOS's Automatic proxy
setting reading `/proxy-ios.pac`
([CONFIGURATION.md#proxy-auto-configuration-pac](CONFIGURATION.md#proxy-auto-configuration-pac),
[NATIVE-WIREGUARD.md](NATIVE-WIREGUARD.md#using-socks-egress-with-proxy-auto-configuration-pac-on-ios)).
Those fail the handshake against a self-signed certificate silently, with no
trust prompt. This guide covers getting a Let's Encrypt certificate onto
`ntwire-server` for that case, alone or behind `ntwire-relay`.

Any ACME client and any of its supported challenge types work; the examples
below use `certbot` because it is the most widely available.

## Server alone (direct inbound connectivity)

If the server has a public hostname and accepts direct inbound connections,
plain HTTP-01 works. `ntwire-server` never binds port 80 itself
(`listen.https` defaults to `:8443`), so `certbot`'s standalone plugin can
use it for the challenge as long as your firewall allows brief inbound
traffic on port 80 from the internet:

```sh
sudo certbot certonly --standalone -d server.example.com
```

If port 80 is already serving something else, use `--webroot` against that
web server's document root instead of `--standalone`.

Point the server at the issued files:

```yaml
tls:
  cert_file: /etc/letsencrypt/live/server.example.com/fullchain.pem
  key_file: /etc/letsencrypt/live/server.example.com/privkey.pem
```

`ntwire-server` re-reads `tls.cert_file`/`tls.key_file` from disk on every
[hot reload](CONFIGURATION.md#hot-reload) — no restart needed for a renewed
certificate to take effect. Trigger that reload from certbot's renewal hook:

```sh
sudo certbot certonly --standalone -d server.example.com \
  --deploy-hook "touch /etc/ntwire/ntwire.yaml"
```

(`kill -HUP <pid>` or any other write/rename of the config file works
equally well — see [Hot reload](CONFIGURATION.md#hot-reload).) Ensure the
`ntwire-server` process user can read the certbot output directory, or copy
the two files to a location it owns with mode `0600` as part of the hook.

## Server behind ntwire-relay (no inbound connectivity)

A server reachable only through `ntwire-relay` has no port 80 (or any other
inbound port) for HTTP-01 to challenge, and the relay's `listen.public` can't
carry a plain HTTP-01 request either — it only understands a TLS
ClientHello and splices raw bytes to the registered tenant by SNI; anything
else is reset unanswered (see
[RELAY.md#tls-certificates-for-the-public-listener-pac-and-browser-clients](RELAY.md#tls-certificates-for-the-public-listener-pac-and-browser-clients)).
**Use DNS-01 instead.** This also happens to be the only way to get a
wildcard certificate, which is usually what you want here: one certificate
for `*.relay.example.com` covers every tenant subdomain, so every server
registered on that relay can share it.

With a DNS provider that has a certbot plugin (Cloudflare, Route 53, etc.):

```sh
sudo certbot certonly --dns-cloudflare \
  --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
  -d '*.relay.example.com'
```

Without a plugin, `--manual` walks you through publishing the TXT record
yourself (fine for a one-off issuance; a plugin is worth it once renewal
needs to be unattended). Either way, the certificate and key land once,
locally to whichever host ran the ACME client:

```yaml
tls:
  cert_file: /etc/ntwire/relay-wildcard-fullchain.pem
  key_file: /etc/ntwire/relay-wildcard-privkey.pem
```

Deploy this same `fullchain.pem`/`privkey.pem` pair to **every tenant's
`ntwire-server`** registered on that relay — each terminates its own TLS
independently through the relay's raw splice, so each needs its own copy of
the certificate on disk. This goes in the origin server's `tls:` block, never
on the relay: the relay's own `tls:` block only covers `listen.agents` (the
server-registration port) and has no effect on what a client sees. As above,
`tls.cert_file`/`tls.key_file` hot-reload live, so a renewal hook that
copies the renewed files out to each server and touches its config file (or
sends `SIGHUP`) is enough — no server restart required.

## Optional: a CA-trusted certificate for the relay's own `listen.agents`

This is a separate, optional concern from everything above: it authenticates
the `ntwire-server` ↔ `ntwire-relay` registration hop, not anything a client
sees. By default that hop is authenticated with `relay.fingerprint`
(pinning, same idea as the client/server TOFU model). To use normal PKI
verification instead, leave `relay.fingerprint` empty and give the relay a
real certificate for its own public hostname — the one used in
`relay.url: wss://relay.example.com:8444` — the same way as the direct-server
case above, since the relay's `listen.agents` port is ordinarily
internet-facing and doesn't conflict with port 80:

```sh
sudo certbot certonly --standalone -d relay.example.com
```

```yaml
# ntwire-relay.yaml
tls:
  cert_file: /etc/letsencrypt/live/relay.example.com/fullchain.pem
  key_file: /etc/letsencrypt/live/relay.example.com/privkey.pem
```

**This one does not hot-reload.** Unlike `ntwire-server`'s `TLSManager`,
`ntwire-relay` loads the `listen.agents` certificate once at startup
(`pkg/relay/tls.go`); a renewed certificate needs the process restarted, not
just the config file touched. Make the renewal hook restart the service
instead:

```sh
sudo certbot certonly --standalone -d relay.example.com \
  --deploy-hook "systemctl restart ntwire-relay"
```

(substitute a container/orchestrator restart as appropriate for your
deployment — e.g. `docker restart ntwire-relay` or a Kubernetes rolling
restart of the relay Deployment). Restarting the relay process drops every
connection through it, including already-open client sessions spliced
through `listen.public` and each server's `listen.agents` registration; both
sides redial automatically (see
[High availability and recovery](RELAY.md#high-availability-and-recovery)),
so plan the restart for a low-traffic window on a single-relay deployment,
or roll it through one pool member at a time behind `relay.endpoints`.
