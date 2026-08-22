---
title: iOS and iPadOS client feasibility
description: Apple Network Relay feasibility, architecture, and delivery plan
type: architecture
---

# iOS and iPadOS client

> **Archived (temporary).** The native `ios/NTWire` app and its MASQUE
> gateway plan below are paused; the code stays in this repository and its
> CI workflow is disabled but not deleted, so this can resume later. Until
> then, iOS/iPadOS devices should connect with the **official WireGuard
> app** against `ntwire-server`'s native WireGuard support instead of this
> client — see [NATIVE-WIREGUARD.md](NATIVE-WIREGUARD.md) for the server
> config and profile to import, and
> [RELAY.md](RELAY.md#native-wireguard-udp-endpoints) for reaching a server
> behind `ntwire-relay`. The rest of this document is the frozen feasibility
> and design record for the archived client.

## Decision: GO, with a new optional MASQUE gateway

An ntwire iOS/iPadOS client based on `NERelayManager` is feasible for an
ordinary paid Apple Developer **Individual** membership and App Store or
TestFlight distribution. It is not a programmable replacement for
`NEPacketTunnelProvider`: it configures Apple’s system-managed Network Relay,
which proxies TCP with HTTP `CONNECT` and UDP with MASQUE `connect-udp`.
Accordingly, it cannot connect directly to the existing ntwire WireGuard UDP
endpoint or its token-authenticated WebSocket endpoint.

The required `relay` value of the Network Extensions entitlement is listed by
Apple as an App Store Network Extension capability. Current Apple provisioning
guidance says Xcode can enable Network Extensions for the App ID and create the
corresponding provisioning profile; it does not state that `relay` needs an
Organization membership, MDM, supervision, or a separate Apple approval. An
individual account still needs the normal paid-program membership, correctly
provisioned App ID, code signing, App Store review, and truthful privacy
disclosures. Apple’s Developer Program terms also require that a Network
Extension app be primarily for networking and have the entitlement.

This was a **GO for the platform and distribution constraint**, not a claim
that the server could already serve Network Relay traffic at the time this
decision was made. The MASQUE gateway has since been implemented
(`pkg/server/masque_gateway.go`, `pkg/server/masque.go`), and the checked-in
iOS app now generates its own key/CSR, obtains a certificate, assembles it
into a PKCS#12 identity, and installs a `NERelayManager` configuration
immediately after authentication (`NTWireApp.swift`'s `configureRelay`) — see
[Delivery gates](#delivery-gates). None of this has been validated against a
physical device yet; that real-device interoperability proof is the actual
remaining gate before this data path ships, not whether the code exists — see
the acceptance criteria
[below](#identity-packaging-spike-required-acceptance-criteria).

## Apple requirements and evidence

| Item | Finding | ntwire consequence |
| --- | --- | --- |
| API | `NERelayManager` creates one persisted relay configuration, with one or two `NERelay` hops, domain/FQDN matching, exclusions, and on-demand rules. | The app configures the OS; it does not run an arbitrary packet-processing provider. |
| Availability | Network Relay is available from iOS 17 and iPadOS 17. Exact deployment availability must be checked again when selecting the Xcode SDK. | Initial deployment target: iOS/iPadOS 17.0. FQDN-specific matching is a later iOS/iPadOS 18.4 enhancement. |
| Entitlement | `com.apple.developer.networking.networkextension` containing `relay`, on the app target. | Add only `relay`; do not add packet-tunnel, app-proxy, content-filter, DNS-proxy, App Group, or managed-device capabilities merely as a workaround. |
| Distribution | Apple documents adding Network Extensions to an App Store app through Xcode. Apple’s current provisioning guidance describes automatic signing/profile authorization for ordinary Network Extension providers. | Individual TestFlight/App Store distribution is compatible in principle. A release must be validated with a real individual-team App ID and archive before any distribution promise. |
| MDM/supervision | Apple separately documents an MDM Relay payload and managed-app assignment. That is an alternate deployment channel, not a stated prerequisite for an app-owned `NERelayManager` configuration. | Do not require MDM, supervision, or an organization account for the app-owned profile. MDM may later deploy centrally managed profiles. |
| Remote protocol | `NERelay` describes secure HTTP proxies: HTTP/2/HTTP/3, `CONNECT`, and RFC 9298 `connect-udp` (MASQUE). | ntwire needs a MASQUE-speaking gateway. A WireGuard UDP listener, `/v1/wg` WebSocket, and `ntwire-relay` alone are insufficient. |

Primary Apple references:

- [NERelayManager](https://developer.apple.com/documentation/networkextension/nerelaymanager)
- [NERelay](https://developer.apple.com/documentation/networkextension/nerelay)
- [Network Extensions entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension)
- [Configuring network extensions](https://developer.apple.com/documentation/xcode/configuring-network-extensions)
- [Use network relays on Apple devices](https://support.apple.com/guide/deployment/use-network-relays-dep91a6e427d/1/web/1.0)
- [Relay device-management payload](https://support.apple.com/guide/deployment/relay-payload-settings-dep131693e6b/1/web/1.0)
- [Apple Developer Program Information](https://developer.apple.com/programs/information/Apple_Developer_Program_Information_8_12_15.pdf)

Apple’s device-management documentation describes Network Relay as a
MASQUE-based alternative to VPN, domain-based routing, and an optional managed
app assignment. Its MDM payload supports iOS/iPadOS 17 onward; the MDM
availability must not be conflated with the app API’s entitlement and
distribution model.

## What does not map directly from ntwire today

The existing protocol remains authoritative and unchanged for desktop clients:

- `GET /v1/info`, `POST /v1/auth`, `POST /v1/auth/oidc`, `POST /v1/renew`,
  and `POST /v1/disconnect` establish an opaque bearer-token session.
- The auth response returns a per-session WireGuard peer, tunnel IP, virtual
  ports, a direct UDP endpoint, and optionally a WebSocket endpoint.
- `pkg/wgnet` owns a userspace WireGuard device plus gVisor netstack;
  `pkg/client` opens local listeners; `pkg/wstransport` transports WireGuard
  datagrams over WebSocket/relay paths.
- `target: socks` is a server-side SOCKS4/5 TCP service with its own
  destination filters; UDP ASSOCIATE is deliberately refused.

Network Relay does not offer ntwire an `NEPacketTunnelFlow`, a way to host
local listeners, or a callback for custom WireGuard framing. Compiling the
current `pkg/client`, `pkg/wgnet`, or `pkg/wstransport` with gomobile would not
solve that mismatch: they contain CLI/browser/filesystem/listener assumptions
and terminate traffic in a gVisor netstack rather than accepting relay
`CONNECT`/`connect-udp` streams.

The iOS app should therefore implement a small native Swift control plane for
the documented HTTPS JSON API. Share protocol fixtures with Go rather than
embedding the CLI. Go reuse is appropriate only after extracting a
platform-neutral, no-UI/no-filesystem control-plane package; it is not needed
for the initial Swift client.

## Required optional architecture

```
iOS/iPadOS app ── HTTPS control API ──> existing ntwire-server
     │                                      │
     │ configures NERelayManager             │ existing SSH/OIDC authorization
     ▼                                      ▼
Apple Network Relay ─ MASQUE (H3/H2) ─ ntwire MASQUE gateway ─ ntwire grants
     │                                      │
     └─ only approved private names ────────┘
```

The MASQUE gateway is a new, independently deployable optional component,
ideally close to `ntwire-server` and using a mutually authenticated internal
control channel. It must:

1. implement the HTTP/3 and/or HTTP/2 relay endpoints Apple configures;
2. authenticate each `CONNECT`/`connect-udp` request using an iOS relay
   credential;
3. map only a gateway-owned synthetic FQDN/address and port to a tunnel grant;
4. ask ntwire-server to authorize that credential and grant on every new flow
   (or use a short-lived, revocable signed grant issued by the server);
5. connect only to the already-authorized ntwire target and preserve the
   existing `target: socks` filters; and
6. expose no raw server tunnel IP, WireGuard key, ntwire bearer token, target,
   identity, or arbitrary egress capability to the device.

The initial opt-in gateway is now capability-gated by `masque-relay-v1` and
serves HTTP/2 `CONNECT` for one fixed TCP target per synthetic FQDN. It
requires TLS client-certificate validation, binds the certificate to a live
ntwire session, verifies that session has the mapped grant, and accepts only
that tunnel's virtual port. It rejects SOCKS grants, `connect-udp`, HTTP/3,
and arbitrary destination requests. Those restrictions are deliberate first
milestone boundaries, not fallback behavior. Old clients ignore the optional
capability and old servers do not advertise it, so existing CLI, GUI, server,
relay, WireGuard, UDP-relay, and WebSocket behavior stays unchanged.

An enabled server needs a separate public TLS listener and explicit mapping:

```yaml
masque:
  enabled: true
  listen: ":8445"
  http2_url: "https://relay.example.test:8445"
  match_domains: ["reports.private.example.test"]
  client_ca_file: /etc/ntwire/masque-ca.pem
  issuer_cert_file: /etc/ntwire/masque-ca.pem
  issuer_key_file: /etc/ntwire/masque-ca-key.pem
  certificate_ttl: 15m
  tunnels:
    reports.private.example.test: reports
```

The issuer must be a CA certificate capable of signing client certificates;
the relay listener's normal server certificate remains `tls.cert_file` and
`tls.key_file`. The CA private key is server-side secret material and must not
be committed or reused as the public HTTPS server key.

### Credentials and session lifetime

An existing ntwire bearer token must not be copied blindly into relay headers:
it has a short session lifetime and Network Relay is OS-managed while the app
is suspended. The gateway design must first define a **mobile relay
credential** with audience, profile ID, grant IDs, expiry, rotation, and
revocation semantics. ntwire has selected a short-lived mTLS credential bound
to the gateway and issued only after existing OIDC/SSH authorization. The
device creates the private key and CSR locally; authenticated
`POST /v1/masque/certificate` returns a client-authentication certificate and
the public issuer certificate. The private key and bearer token are never in
the response. The server clamps expiry to the shorter of the configured
certificate TTL, the existing ntwire session, and the issuer certificate.

The certificate endpoint alone does **not** configure a relay; the implemented
gateway validates the certificate against its configured client CA and
re-checks the session/grant binding before accepting `CONNECT`. Packaging the
identity for `NERelay.identityData` requires PKCS#12 bytes, and the public
APIs documented in the installed SDK expose that input without themselves
establishing a safe, general PKCS#12 *creation* path for a Keychain-held
device key — so the app now does this itself:
`ios/NTWire/Sources/NTWireCore/PKCS12.swift` is a from-scratch RFC 7292
encoder that combines a locally generated software key, the certificate
returned by the server, and the issuer certificate into a password-protected
container, immediately discarding raw private-key bytes afterward
(`MASQUEIdentity.swift`, `NetworkRelayController.swift`). This has not yet
been proven on a real device. If the acceptance criteria below cannot be met
on physical hardware, short-lived mTLS is not viable for this product and the
design must return to the feasibility gate rather than send the private key
to the server. It must never put refresh tokens, SSH private keys, or a
long-lived ntwire bearer token in relay preferences.

### Identity-packaging spike: required acceptance criteria

Apple documents `NERelay.identityData` as PKCS#12 data and exposes
`identityDataPassword` separately. Apple also documents
`SecKeyCopyExternalRepresentation` for eligible keys, while noting that it
fails for Secure Enclave and other non-exportable keys. This leaves one narrow
possible implementation: generate an **exportable, software-backed** device
key locally; use it to create the CSR; combine its in-memory representation,
the returned leaf certificate, and issuer certificate into a password-protected
PKCS#12 container locally; then immediately discard raw private-key bytes and
keep the container/password only in the appropriate system-managed/keychain
storage needed to configure the relay.

An ad-hoc, unreviewed ASN.1/PKCS#12 encoder is exactly what has been written
so far (`PKCS12.swift`) — its existence is not itself proof it is safe to
ship. Before this path is enabled in a release, a signed Individual-team
build on a physical iOS/iPadOS 17+ device must still prove all of the
following:

1. The app can generate the required software-backed key and CSR locally; the
   server receives only the CSR and never a private key.
2. The locally assembled, password-protected PKCS#12 value is accepted by
   `NERelay.identityData` and its password by `identityDataPassword`.
3. The relay completes mTLS to the test gateway and the gateway observes the
   certificate issued for that exact CSR.
4. A wrong password, expired certificate, revoked/expired ntwire session,
   untrusted issuer, and changed relay TLS key each fail closed.
5. Device logs, crash reports, profile JSON, and diagnostics contain neither
   the bearer token, PKCS#12 bytes/password, nor raw key bytes.

The key must not be generated in the Secure Enclave for this path: Apple says
such a key cannot be exported, whereas Network Relay requires a PKCS#12
container rather than a keychain identity reference. If this spike cannot be
implemented with a reviewed local implementation and the stated properties,
the mTLS design is a NO-GO; do not replace it by sending a client private key
to ntwire-server or by weakening gateway authentication.

Relevant Apple references:

- [NERelay.identityData](https://developer.apple.com/documentation/networkextension/nerelay/identitydata)
- [NERelay.identityDataPassword](https://developer.apple.com/documentation/networkextension/nerelay/identitydatapassword)
- [Storing Keys as Data](https://developer.apple.com/documentation/security/storing-keys-as-data)

## Split access and DNS

Configure only explicit ntwire private names in `matchDomains` (and, when the
deployment target permits it, exact FQDN rules). Do not leave matches empty,
which would relay normal Internet traffic. `excludedDomains` is a defence in
depth measure, not a substitute for a positive allow-list.

The gateway must provide a private DNS/DoH design before implementation. The
synthetic DNS prefix properties on `NERelay` are promising for gateway-owned
private names, but their exact HTTP request form and DNS behavior require a
real-device interoperability spike. Private names must resolve only while a
matching authorized relay profile is active; do not install a global DNS
resolver or leak private queries to public DNS. Raw IP access and arbitrary
domain routing are out of scope for the first data-path milestone.

## Authentication, profiles, and trust

The future app will use Swift, SwiftUI, async/await, Network.framework, and
Keychain. Its profile model follows `ntwire-gui`: display name, HTTPS server
URL, selected auth method/issuer, selected grants, TLS trust record, relay
state, and safe diagnostics.

- **OIDC first:** use `ASWebAuthenticationSession` with Authorization Code +
  PKCE and an iOS public-client redirect URI. Store refresh/session material
  only in Keychain. The provider must never present authentication UI.
- **SSH second:** The client imports unencrypted PKCS#8 Ed25519, RSA, and
  NIST P-256 ECDSA keys and emits the corresponding OpenSSH signature format
  against ntwire’s canonical signing payload. Private material stays in
  Keychain and is never exported/logged unnecessarily. Encrypted OpenSSH
  containers currently remain limited to the existing Ed25519 path.
- **TLS:** preserve the existing TOFU/pinning model, matching the `ntwire`
  CLI's known_servers prompt (cmd/ntwire/main.go). ntwire server listeners
  default to a self-signed certificate, so system chain validation is not
  meaningful here; a native `URLSession` trust delegate never auto-accepts a
  certificate, including on first connect — it always fails the handshake
  closed and reports the presented SHA-256 fingerprint (matching the
  `tls_fingerprint` the server logs and `TLSManager.Fingerprint()` reports)
  so the UI can prompt for explicit trust before retrying once, pinned. A
  later mismatch prompts again with both fingerprints shown, same as a
  changed SSH host key. There is no iOS equivalent of silently enabling
  `--insecure`.
- **OIDC client secrets:** an App Store binary is a public client. Never embed
  `NTWIRE_OIDC_CLIENT_SECRET` or a provider secret; issuers that require one
  need a different public-client registration.

## Background behavior

Network Relay allows the OS networking stack to maintain configured relay
connections; it does not grant the containing app perpetual execution. The
app cannot depend on timers to renew tokens while suspended. Login-required,
expired, revoked, or changed-trust states must stop/reject new relay flows and
be resolved when the user next opens the app, unless the final Apple-supported
credential mechanism can refresh them without app execution.

Do not use location, audio, VoIP, Bluetooth, background fetch, or a silent
loop solely to keep ntwire alive. Background URL sessions, push notifications,
or BackgroundTasks may be used only for their documented independent purposes
and are not a connection keepalive solution. The legitimate continuous
networking mechanism here is the OS-owned Network Relay itself.

## Closest fallback if the gateway spike fails

If the MASQUE gateway or credential lifecycle cannot be proven on a real
individual-account device, do not substitute `NEPacketTunnelProvider`
automatically. The closest compliant non-VPN product is an app-contained
local SOCKS5 client using the existing userspace networking/control path, but
it can serve only connections initiated by that app: iOS does not let an
ordinary application expose a localhost proxy for Safari and other apps, and
the app will be suspended in the background. It is useful for an in-app SSH or
database experience, not system-wide ntwire access.

`NEPacketTunnelProvider` plus a WireGuard backend is a separate, potentially
viable product architecture, but it violates this project’s chosen Network
Relay direction and is deliberately not introduced here.

## Delivery gates

1. **Gateway protocol design:** specify the optional capability, credential,
   target mapping, DNS behavior, error taxonomy, and revocation checks.
2. **Real-device spike:** using an Individual-team signed build, prove one
   `CONNECT` request through a minimal MASQUE gateway to one fixed ntwire
   grant on iOS 17+; test chain validation, pin mismatch, expiry, and no-match
   behavior.
3. **Minimal app:** `ios/NTWire/` now contains an Xcode iOS/iPadOS app target
   and a dependency-free Swift package. It has profile/add-edit, authentication
   state, grant, and diagnostics screens; strict HTTPS URL validation;
   `/v1/info` discovery; Keychain and profile-store abstractions; and unit
   tests. Profiles persist in Application Support; users can edit or delete a
   profile, and can import, replace, or remove an SSH private key through the
   Files picker. SSH private-key bytes are kept only in the Keychain, never in
   the profile file or diagnostics. CI builds the app unsigned for the
   simulator and runs the core tests. SSH authentication creates a signed
   session using a Keychain-held unencrypted PKCS#8 Ed25519, RSA, or NIST
   P-256 ECDSA key and a per-profile WireGuard identity; the issued session
   token is also Keychain-only. Encrypted OpenSSH Ed25519 keys are supported
   with a request-only passphrase; RSA and ECDSA imports must remain
   unencrypted PKCS#8. `URLSessionTransport` pins the server's certificate
   per the TOFU model above: an unrecognized or changed certificate always
   fails the handshake closed and surfaces an `UntrustedServerCertificateError`
   naming the fingerprint(s); the profile detail view prompts for explicit
   trust and retries once, only persisting the pin after the user agrees.
   OIDC UI remains unimplemented (no `ASWebAuthenticationSession`/OIDC code
   exists in the app yet). End-to-end relay installation is implemented: on
   successful SSH authentication against a server advertising
   `masque-relay-v1`, the app generates a key/CSR, obtains a certificate,
   assembles a PKCS#12 identity, and installs it through a thin
   `NERelayManager` adapter (`NetworkRelayController.swift`) that accepts only
   explicit H2/H3 gateway URLs and positive domain matches, never a guessed
   endpoint or bearer-token header. This path has not been validated on a
   physical device — see [above](#identity-packaging-spike-required-acceptance-criteria).
4. **Data plane:** implement the optional gateway and one TCP grant, then add
   split DNS, multiple grants, diagnostics, renewal/revocation, and transport
   accounting.
5. **Release check:** archive with an Individual-team profile, install through
   TestFlight, and re-validate App Store review and entitlement behavior. Do
   not store signing assets or Apple credentials in this repository.

## Security additions

The iOS client/gateway must preserve the server as the authorization authority
and add: Keychain-only secrets; certificate pinning that replaces ATS's
PKI-based TLS validation rather than layering on top of it (the server URL is
user-specified and typically self-signed, so the app carries a broad
`NSAllowsArbitraryLoads` ATS exception and enforces trust itself via
`PinningURLSessionDelegate`, per the TLS bullet above); secure
randomness; bounded/validated server responses; expiry and logout cleanup;
minimal entitlement use; and diagnostics that omit tokens, private keys,
identities, private targets, and raw server errors. Gateway logs and metrics
must use the same low-cardinality, safe-category discipline as ntwire’s
existing observability.

## Build and signing

`ios/NTWire/NTWire.xcodeproj` is the native iOS/iPadOS app and
`ios/NTWire/Package.swift` is its independently testable core. CI runs an
unsigned simulator `xcodebuild` plus `swift test` on a macOS runner. A
developer selects their own Team and bundle identifier in Xcode, keeps the
checked-in Network Extensions entitlement limited to `relay`, and lets Xcode
generate matching provisioning profiles. TestFlight and App Store archives
require the developer’s own signing configuration; no certificate, profile,
private key, token, or Apple credential belongs in source control.
