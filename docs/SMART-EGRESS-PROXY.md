# Smart Egress Proxy

Smart Egress Proxy provides one local address for SOCKS5 CONNECT, HTTP/1.x forwarding, HTTP CONNECT, and HTTP WebSocket upgrades. It routes new destination connections through a group of explicitly selected ntwire SOCKS tunnels. The listener stays up across profile connections and reconnects. An established stream keeps its egress until it closes.

The feature starts disabled. It listens on numeric loopback addresses and can use approved userspace WireGuard connections or explicitly configured client-native routes. Explicit membership works with existing compatible SOCKS grants. Automatic enrollment additionally requires servers that advertise an egress policy class.

## Select the group

Only group tunnels whose operators confirm that they share the same intended trust and destination policy. A public internet proxy and an internal-services proxy generally belong in different workflows. The current server grant identifies a SOCKS tunnel, but it cannot certify policy equivalence or distinguish a transparent upstream. An explicitly approved transparent upstream can participate if it supports SOCKS5 CONNECT without a separate SOCKS login.

A policy denial stops the request. A timeout or connection close after destination submission also stops the request because the client may receive no definitive policy result. The router can try a backup after a positively identified infrastructure failure before destination submission. An unavailable group returns an error. A permissive member could accept a destination that an undisclosed restrictive policy elsewhere would deny if the permissive member is selected first. Enforce any required group-wide policy at every member.

The unauthenticated data endpoint is local to the machine. On a shared host, other local processes may be able to use it. The GUI management API and standalone attachment and control services require local authentication.

## Desktop and headless GUI

Connect the profiles you want to use. In Settings, expand **Smart Proxy** below profile management. Choose a group, add and approve trusted SOCKS tunnels in **Tunnels**, check **Activate this group**, and select **Save changes**. Turn on **Enable Smart Proxy** to run the saved active groups. This master switch starts off, including for existing settings files without the switch. Turning it off stops all group and PAC listeners, keeps the saved group settings, and hides Smart Proxy from the tray.

The **Tunnels** and **Destination rules** tabs show tables. Use **Add** or **Edit** to open an item form. Item edits go into the group draft. Use the row arrows to reorder items, then select **Save changes** to apply the draft. Destination rules run in the order shown.

Select **Open live dashboard** to open the selected group in a new browser tab. Traffic shows combined sent and received rates by default. Latency compares setup time across all tunnels, with one line per tunnel. Select an individual tunnel in either chart for its traffic or detailed timings. The dashboard also shows active connections, tunnel usage, diagnostics, and temporary preferences.

ntwire GUI samples trend metrics every two seconds and retains the last five minutes in memory, including while the dashboard is closed. History resets when ntwire GUI restarts. Gray bands mark periods with no recorded samples. Red bands in Tunnel latency mark a reported disconnection or reconnect. Hover over a red band to see the affected tunnel.

When the master switch is on, the tray shows one **Smart Proxy** menu. Choose **Group** to switch which group its actions apply to. **Activate** and **Disconnect** change the selected group's saved activation. **Open dashboard** also works when that group is inactive. **Open isolated browser** is available while the group is listening.

**Export saved settings** downloads a JSON file with the saved groups, routing rules, probe URLs, and names of referenced profiles. It excludes saved profile credentials and the master switch. **Import settings** loads a draft and matches profile names and server URLs where there is one local match. Review unmatched IDs and approve trusted tunnels and enrollments before saving.

You can switch groups or close the panel while editing. **Save changes** applies all pending edits, and **Discard changes** restores the saved configuration. Copy and browser actions and live tunnel preferences use the running configuration. The isolated browser uses the global executable, storage, and argument preferences with its own persistent profile. A preferred tunnel or temporary exclusion affects new connections. Closing Settings leaves the proxy running.

For headless GUI, configure the top-level `smart_proxy` block and set `smart_proxy_enabled: true` in `gui.yaml` when ready to run it. Reference the actual profile IDs. The authenticated Settings API provides configuration at `/api/smart-proxy`, master activation via `PUT /api/smart-proxy/master` with an `enabled` boolean, and status at `/api/smart-proxy/status` and on the SSE stream. The option called **Proxy settings** on each profile configures ntwire's own HTTPS/WSS connection.

The isolated Chromium browser prefers SOCKS5 when it is enabled and the group can only route directly or deny, or when every non-excluded member currently advertises numeric-domain support. With both protocols enabled, a disconnected or incompatible member causes new launches to use HTTP. A single-protocol group uses its configured protocol. Reopen the isolated browser to pick up a new protocol choice. The launch removes Chromium's implicit loopback bypass for proxied requests. The proxy governs traffic that applications submit to its listener.

Chromium sends numeric IPv4 and IPv6 URLs in the SOCKS5 domain field. Earlier Smart Proxies rejected this encoding because converting the field to binary could change upstream domain-suffix decisions. The proxy now uses the canonical IP for routing and sends the original field to a compatible selected member. The egress server requires both numeric authorization and the policy result for the original text. A mismatch is denied. IPv4-mapped IPv6 uses the IPv4 address for routing and filtering. Ordinary tunneled hostname requests still resolve at the egress. Direct numeric destinations work without an upstream capability.

If the selected member is an older server, an older attached publisher, or a transparent or chained upstream without the capability, numeric-domain CONNECT fails with SOCKS5 reply `0x08`. The proxy keeps the same member ranking and never tries a backup merely to get around that compatibility failure. HTTP CONNECT and binary SOCKS5 continue to work through those members. Keep HTTP enabled in mixed groups for Chromium numeric URLs. SOCKS5-only groups can use numeric URLs when the selected member supports the capability. Established browser windows retain their launch settings as membership changes.

To block local hostname lookups by the isolated browser, enable **Block local DNS in the isolated browser** in the group's **Setup** tab and save. The option defaults to off and takes effect when you fully close and reopen the isolated browser. It uses Chromium's `--host-resolver-rules=MAP * ~NOTFOUND` with an exception for the numeric proxy address, which requires no DNS lookup. Both HTTP and SOCKS5 still send destination hostnames through the proxy. A custom browser must support Chromium's host resolver rules. This setting controls the browser's resolver and does not provide system-wide DNS isolation. For headless GUI settings, set `browser_block_local_dns: true` in the applicable group.

## Standalone CLI

Run the following commands in separate terminals. Use separate connection configuration files with the normal SSH or OIDC options for each server.

```sh
ntwire connect --config client-a.yaml --publish-egress server-a https://a.example.net
ntwire connect --config client-b.yaml --publish-egress server-b https://b.example.net
ntwire proxy --config egress.yaml
```

The publishers own authentication, renewal and their individual listeners. They can start before or after the aggregate router. Publishing is opt-in and uses a distinct status file per publisher by default. Use `ntwire status --status-file <path>` to query a particular publisher's ordinary status.

```sh
ntwire proxy status --config egress.yaml --json
ntwire proxy reload --config egress.yaml
curl --proxy socks5h://127.0.0.1:1080 https://example.org/
curl --proxy http://127.0.0.1:1080 https://example.org/
```

For a compatible group, the following commands illustrate numeric and hostname URLs. Replace the documentation addresses with authorized destinations reachable by your egress server.

```sh
curl --noproxy '' --proxy socks5h://127.0.0.1:1080 http://192.0.2.10/
curl --noproxy '' --proxy socks5h://127.0.0.1:1080 'http://[2001:db8::10]/'
chromium --user-data-dir="$HOME/.ntwire/smart-proxy-example" \
  --proxy-server=socks5://127.0.0.1:1080 '--proxy-bypass-list=<-loopback>' \
  'http://192.0.2.10/' 'http://[2001:db8::10]/' 'https://example.org/'
```

Save edits before reloading. If validation, binding, or persistence fails, all existing listeners continue serving. To shut off the listener through reload, set `enabled: false`. Ctrl-C exits the aggregate process. The same-account publisher and router discovery records live under `~/.ntwire/egress`. They contain scoped local authentication material. Keep those files private. The attachment pins the publishing instance's local TLS certificate and revalidates the current grant for every new stream.

## Configuration example

```yaml
smart_proxy:
  enabled: true
  listen: "127.0.0.1:1080"
  protocols: [socks5, http]
  egress:
    selection: sticky-fastest
    members:
      - profile_id: server-a
        expected_server: https://a.example.net
        tunnel: internet
        priority: 100
      - profile_id: server-b
        expected_server: https://b.example.net
        tunnel: internet
        priority: 90
  failover:
    enabled: true
    max_attempts: 3
    attempt_timeout: 3s
    total_timeout: 10s
  health:
    probe_targets: []
    interval: 30s
    failure_threshold: 3
    recovery_interval: 30s
  routing:
    affinity_ttl: 5m
    hysteresis_percent: 20
  limits:
    connections: 1024
    concurrent_attempts: 32
```

- Each group accepts up to 1,024 active connections by default. To change a saved limit, set **Maximum connections** in the group settings or edit `limits.connections` in YAML. The maximum is 4,096. Once the group is full, it closes new connections until a slot opens.
- **Automatically adjust connection and setup limits** in the group's **Limits** tab enables Auto mode. In YAML, set `limits.auto: true`. Both numeric settings become ceilings. Auto starts at up to 512 connections and 32 simultaneous setups. To allow setup concurrency to grow above 32, raise **Maximum simultaneous setup attempts** (for example, to 128). YAML with Auto enabled and no explicit setup ceiling defaults to 128.
- Auto uses recent demand to grow limits. It reduces setup concurrency when measured setups slow down or repeatedly encounter transport failures. Groups share a process budget of up to 4,096 inbound connections, constrained by memory and, on Linux and macOS, available file descriptors. Fixed groups count toward the budget and retain their configured limits. Changes affect new admissions. The dashboard and `ntwire proxy status` show effective Auto limits and the reason for the latest adjustment or resource constraint.
- **Sticky fastest** uses recent successful setup latency, variability and infrastructure failures, with a five-minute hostname affinity. Source IP can change between connections. Choose one member for workflows that require a fixed egress identity.
- **Fastest healthy** ranks by measurements without hostname affinity. **Priority** tries higher numbers first, using list order for ties. **Round robin** rotates eligible members.
- **Probes** default off. Configure operator-approved `host:port` destinations or HTTPS URLs. HTTPS uses validated certificates, a bounded HEAD request and no redirect following. Use a common test destination for comparable measurements. Probes suspend during idle periods.
- **Status** distinguishes carrier RTT and control latency from SOCKS setup and total connection establishment. The GUI shows per-member performance and failure details. Use `ntwire proxy status --config egress.yaml --json` for the full standalone status. Affinity keys and requested URLs never appear in status.
- **Protocols.** The aggregate accepts SOCKS5 CONNECT and optionally UDP ASSOCIATE. SOCKS4 and BIND are unsupported on the aggregate.

An omitted block disables the feature. Use a fixed available loopback port such as `127.0.0.1:1080` or `[::1]:1080`. An older GUI that rewrites its configuration can discard fields it does not recognize. Keep a copy of the aggregate settings if downgrading.

## Advanced routing

Use `destination-aware` to rank members using recent observations for the requested host and port. A member with sufficient samples gets a destination-specific latency score. Other members use their general score and any observed destination reachability failures. Policy denials terminate the request and are recorded for diagnosis without influencing this score. The status success rate covers the most recent 32 passive attempts, with a five-minute expiry after inactivity. Destination history is bounded and stays in memory. Status reports aggregate counts without destination names.

For a dedicated browser group, set `selection: sticky-fastest` and `affinity_scope: group`. The first successful egress is reused across eligible destinations until the group is idle for the affinity TTL or selection is forced to change. Applications sharing the listener share that affinity. A destination rule can restrict the eligible members for a particular destination. An exception to the preferred egress leaves the group affinity in place for other destinations.

Destination rules run before ranking. The first matching rule wins. In a rule, an exact name, suffix, or CIDR can satisfy its address selector. A port list and an ASN list each add a constraint. Values within each list are alternatives. Name matching is case insensitive. CIDRs and ASNs use the canonical numeric IP across HTTP and SOCKS5 encodings. Equivalent numeric addresses share affinity and destination history for tunneled routes.

Choose `action: proxy`, `direct`, or `deny`. A proxy rule can restrict destinations to specific approved `members`. Legacy member lists and `deny: true` still work. An omitted unmatched action allows the approved group when there are no rules and denies unmatched requests once rules exist. Set `unmatched: allow` or `proxy` to use the full approved group, `direct` to explicitly use the client network, or `deny` to reject unmatched requests.

### Direct client routes

Direct routes use the client’s OS networking and source address, including any OS-level VPN. The application still connects to the local Smart Proxy. Direct traffic bypasses ntwire servers, relay and WireGuard connections, upstream proxy settings, and proxy environment variables. Server destination policy does not apply. A failed tunnel, server denial, timeout, DNS failure, or missing ASN result never triggers direct access.

Loopback, client interface addresses, link-local and special-use ranges are blocked. Private IPv4 and IPv6 ULA access additionally requires a matched direct rule with a CIDR contained in the applicable private range. The same safeguards apply to every answer from local DNS. The proxy dials only a checked address. An authorized direct hostname can use the client resolver even with Chromium’s own local DNS blocking enabled.

This group works with zero connected profiles. It allows a LAN subnet and a public suffix, then denies other destinations.

```yaml
smart_proxy:
  enabled: true
  listen: 127.0.0.1:1080
  routing:
    unmatched: deny
    rules:
      - cidrs: [192.168.1.0/24]
        action: direct
      - suffixes: [public.example.net]
        action: direct
```

Test an allowed LAN address from the preceding configuration with `curl --noproxy '' --proxy socks5h://127.0.0.1:1080 http://192.168.1.42/`. To test Chromium from a terminal, use a separate browser profile.

```sh
chromium --user-data-dir="$(mktemp -d)" --proxy-server=socks5://127.0.0.1:1080 \
  --proxy-bypass-list='<-loopback>' http://192.168.1.42/
```

For corporate split routing, put a corporate suffix rule with its approved tunnel first and set `unmatched: direct` for the remaining public traffic. To use tunnels by default, set `unmatched: allow` and add only the intended direct exceptions. Direct routes remain operational when all tunnel members disconnect.

### ASN rules and hostname resolution

Numeric rules work with existing servers, subject to the current SOCKS5 numeric-domain capability checks when forwarding that encoding. In this example the named cloud tunnel must already be approved in the group.

```yaml
routing:
  unmatched: allow
  rules:
    - suffixes: [corp.example.net]
      members: [{profile_id: corporate, tunnel: internal}]
    - asns: [13335, 15169]
      action: direct
    - asns: [16509]
      members: [{profile_id: cloud, tunnel: internet}]
    - asns: [64500]
      action: deny
```

An earlier ASN rule whose other conditions match stops routing when the ASN is unknown, unavailable, stale, or unsupported. In this example an unclassified hostname also stops at the first ASN-only rule. Put decisive hostname rules first for traffic that should continue using ordinary remote DNS. The default database is IPv4-only. IPv4-mapped IPv6 is looked up as IPv4. Native IPv6 still works on routes that can be decided without ASN data. ASNs are provider-supplied routing metadata for IP ranges. They offer no proof of service identity and the default format has no multiple-origin representation.

Hostname ASN classification is disabled by default. Use an explicit name scope to opt in.

```yaml
routing:
  asn:
    hostname_resolution: remote
    suffixes: [public.example.net]
    resolver_member: {profile_id: cloud, tunnel: internet}
    on_unknown: deny
  rules:
    - suffixes: [public.example.net]
      asns: [16509]
      members: [{profile_id: cloud, tunnel: internet}]
```

The resolver tunnel must be explicitly approved, policy-compatible, and advertise destination binding. Its server independently authorizes the original hostname and proposed IPs. The selected tunnel connects to the offered address on the same stream. Conflicting route outcomes or an incompatible resolver fail closed. The proxy does not send the name to backup members. Choose `hostname_resolution: local` to expressly permit client DNS for the configured scope. A local result can select a direct route. A resulting proxy route also needs an authorized exact-address offer from the configured resolver tunnel. Remote answers cannot authorize a native direct connection.

Enable `failover.racing` to stagger the first two TCP service preparations by `race_delay`, which defaults to 200 ms. The group sends one destination CONNECT to the winner after closing the losing preparation. Both preparations count against the attempt budget. Destination requests and application payloads are never raced.

### Multiple groups and PAC

The top-level settings define the default group. Named groups have their own listener, rules, members, preferences, history, and isolated browser profile. The default group can stay disabled while named groups run.

```yaml
smart_proxy:
  enabled: false
  pac_listen: "127.0.0.1:1082"
  groups:
    office:
      enabled: true
      listen: "127.0.0.1:1081"
      egress:
        members:
          - profile_id: office-a
            expected_server: https://office.example.net
            tunnel: office
      routing:
        affinity_scope: group
        rules:
          - suffixes: [office.example.net]
            ports: [443]
```

Point an application at `http://127.0.0.1:1082/office.pac` or print the script with `ntwire proxy pac --config egress.yaml --group office`. Each script points to a single local group and delegates destination rules to that group. It uses HTTP when enabled for compatibility with applications that cache the script. It performs no DNS lookups and includes no direct fallback. Use `default.pac` for the default group. The proxy and PAC listeners need distinct addresses.

Use `ntwire proxy prefer --config egress.yaml --group office --profile office-a --tunnel office` for a temporary preference. The `exclude` and `include` commands take the same arguments. `clear-preference` takes just the group and configuration path. These commands use the same authenticated local service as status and reload.

### Automatic enrollment

A server operator can add `egress_class: internet-v1` to a governed SOCKS tunnel. The identifier is an operator declaration of compatible destination policy. Apply the same class only to tunnels with equivalent access and trust. Transparent tunnels are eligible through explicit membership.

Approve the server and class in a group's `egress.enroll` list. For example:

```yaml
egress:
  enroll:
    - profile_id: server-a
      expected_server: https://a.example.net
      egress_class: internet-v1
      priority: 90
```

The router only discovers matching current SOCKS grants from the explicitly approved profile and a verified HTTPS connection. An older server supplies no class. A removed or changed class invalidates its former egress generation when the client receives the new grants. Explicit members take precedence over discovered entries for the same profile and tunnel.

### UDP ASSOCIATE

Set `routing.udp_associate: true` in a SOCKS5 group. Direct UDP works without a server. Tunneled UDP requires a governed native SOCKS tunnel that advertises SOCKS UDP in its authenticated grant. The router pins one eligible tunnel for tunneled datagrams and checks every datagram against the group’s current rules. This allows an association to carry multiple destinations while retaining one source identity. To reach destinations assigned to disjoint member sets, use separate groups. Remote SOCKS UDP framing preserves hostnames for egress-side DNS. The router rejects fragments and pins the sender to the TCP peer's loopback address and declared UDP port, or the first accepted datagram's port when the client supplies zero. The TCP control lifetime and `udp_idle_timeout` bound the relay lifetime.

Each datagram uses the same ordered routing rules as CONNECT. A direct destination uses a bounded, connected client UDP socket. A mixed association can also use one pinned tunnel for proxy destinations. Later packets requiring a different tunnel are dropped. Proxy hostnames that require ASN-bound resolution are currently unsupported over UDP and fail closed. A routing reload or a database change that invalidates the pinned proxy classification can close a mixed association. Ordinary server session renewal with the same authorized peer preserves existing associations.

Numeric datagrams use the same canonical routing as CONNECT. Domain-form IP datagrams require the selected member's numeric-domain capability. The relay preserves the datagram address type so the egress can enforce the original suffix decision even when an equivalent numeric flow already exists. UDP ASSOCIATE still requires a binary source address.

## Developer verification

Run the focused integration test and benchmark against local origins. The relay case starts a real UDP relay and waits for the client to select that carrier.

```sh
go test ./pkg/client ./pkg/egressrouter ./internal/egressattach ./internal/gui/api -run 'SmartProxy|Attachment'
go test ./pkg/client ./pkg/egressrouter -run '^$' -bench 'BenchmarkSmartProxy|BenchmarkSplit' -benchmem
go test -race ./...
```

Run the optional browser integration with `NTWIRE_TEST_CHROMIUM=/path/to/chromium go test ./pkg/client -run TestSmartProxyChromiumNumericURLs`. It uses a temporary profile and local IPv4, IPv6 and hostname origins.

Compare measurements on the same host, carrier and origin. The benchmark reports setup and echo TTFB percentiles, allocations, and round-trip bytes per second. Bulk throughput, CPU/RSS under sustained concurrent load, and latency under controlled packet loss require a separate representative test run.
