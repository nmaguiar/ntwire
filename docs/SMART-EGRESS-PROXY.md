# Smart Egress Proxy

Smart Egress Proxy provides one local address for SOCKS5 CONNECT, HTTP/1.x forwarding, HTTP CONNECT, and HTTP WebSocket upgrades. It routes new destination connections through a group of explicitly selected ntwire SOCKS tunnels. The listener stays up across profile connections and reconnects. An established stream keeps its egress until it closes.

The feature starts disabled. It uses numeric loopback addresses and the existing userspace WireGuard connections. Explicit membership works with existing compatible SOCKS grants. Automatic enrollment additionally requires servers that advertise an egress policy class.

## Select the group

Only group tunnels whose operators confirm that they share the same intended trust and destination policy. A public internet proxy and an internal-services proxy generally belong in different workflows. The current server grant identifies a SOCKS tunnel, but it cannot certify policy equivalence or distinguish a transparent upstream. An explicitly approved transparent upstream can participate if it supports SOCKS5 CONNECT without a separate SOCKS login.

A policy denial stops the request. A timeout or connection close after destination submission also stops the request because the client may receive no definitive policy result. The router can try a backup after a positively identified infrastructure failure before destination submission. An unavailable group returns an error. A permissive member could accept a destination that an undisclosed restrictive policy elsewhere would deny if the permissive member is selected first. Enforce any required group-wide policy at every member.

The unauthenticated data endpoint is local to the machine. On a shared host, other local processes may be able to use it. The GUI management API and standalone attachment and control services require local authentication.

## Desktop and headless GUI

Connect the profiles you want to use. In Settings, expand **Smart Proxy** below profile management. Choose a group, add and approve trusted SOCKS tunnels in **Tunnels**, check **Activate this group**, and select **Save changes**. Turn on **Enable Smart Proxy** to run the saved active groups. This master switch starts off, including for existing settings files without the switch. Turning it off stops all group and PAC listeners, keeps the saved group settings, and hides Smart Proxy from the tray.

The **Tunnels** and **Destination rules** tabs show tables. Use **Add** or **Edit** to open an item form. Item edits go into the group draft. Use the row arrows to reorder items, then select **Save changes** to apply the draft. Destination rules run in the order shown.

Select **Open live dashboard** to open the selected group in a new browser tab. Traffic shows combined sent and received rates by default. Latency compares setup time across all tunnels, with one line per tunnel. Select an individual tunnel in either chart for its traffic or detailed timings. The dashboard also shows active connections, tunnel usage, diagnostics, and temporary preferences. Trend charts collect up to five minutes of samples while the tab is open.

When the master switch is on, the tray shows one **Smart Proxy** menu. Choose **Group** to switch which group its actions apply to. **Activate** and **Disconnect** change the selected group's saved activation. **Open dashboard** also works when that group is inactive. **Open isolated browser** is available while the group is listening.

**Export saved settings** downloads a JSON file with the saved groups, routing rules, probe URLs, and names of referenced profiles. It excludes saved profile credentials and the master switch. **Import settings** loads a draft and matches profile names and server URLs where there is one local match. Review unmatched IDs and approve trusted tunnels and enrollments before saving.

You can switch groups or close the panel while editing. **Save changes** applies all pending edits, and **Discard changes** restores the saved configuration. Copy and browser actions and live tunnel preferences use the running configuration. The isolated browser uses the global executable, storage, and argument preferences with its own persistent profile. A preferred tunnel or temporary exclusion affects new connections. Closing Settings leaves the proxy running.

For headless GUI, configure the top-level `smart_proxy` block and set `smart_proxy_enabled: true` in `gui.yaml` when ready to run it. Reference the actual profile IDs. The authenticated Settings API provides configuration at `/api/smart-proxy`, master activation via `PUT /api/smart-proxy/master` with an `enabled` boolean, and status at `/api/smart-proxy/status` and on the SSE stream. The option called **Proxy settings** on each profile configures ntwire's own HTTPS/WSS connection.

The isolated Chromium browser uses HTTP when the group supports it, including when SOCKS5 is also enabled. HTTP lets the browser reach literal IP destinations through the group's routing rules. The browser uses SOCKS5 for SOCKS5-only groups, where Chromium's encoding of literal IP addresses is unsupported. The launch removes Chromium's implicit loopback bypass for proxied requests. The proxy governs traffic the application submits to it. Some applications resolve names locally or bypass proxies for certain traffic.

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
    connections: 256
    concurrent_attempts: 32
```

- **Sticky fastest** uses recent successful setup latency, variability and infrastructure failures, with a five-minute hostname affinity. Source IP can change between connections. Choose one member for workflows that require a fixed egress identity.
- **Fastest healthy** ranks by measurements without hostname affinity. **Priority** tries higher numbers first, using list order for ties. **Round robin** rotates eligible members.
- **Probes** default off. Configure operator-approved `host:port` destinations or HTTPS URLs. HTTPS uses validated certificates, a bounded HEAD request and no redirect following. Use a common test destination for comparable measurements. Probes suspend during idle periods.
- **Status** distinguishes carrier RTT and control latency from SOCKS setup and total connection establishment. The GUI shows per-member performance and failure details. Use `ntwire proxy status --config egress.yaml --json` for the full standalone status. Affinity keys and requested URLs never appear in status.
- **Protocols.** The aggregate accepts SOCKS5 CONNECT and optionally UDP ASSOCIATE. SOCKS4 and BIND are unsupported on the aggregate.

An omitted block disables the feature. Use a fixed available loopback port such as `127.0.0.1:1080` or `[::1]:1080`. An older GUI that rewrites its configuration can discard fields it does not recognize. Keep a copy of the aggregate settings if downgrading.

## Advanced routing

Use `destination-aware` to rank members using recent observations for the requested host and port. A member with sufficient samples gets a destination-specific latency score. Other members use their general score and any observed destination reachability failures. Policy denials terminate the request and are recorded for diagnosis without influencing this score. The status success rate covers the most recent 32 passive attempts, with a five-minute expiry after inactivity. Destination history is bounded and stays in memory. Status reports aggregate counts without destination names.

For a dedicated browser group, set `selection: sticky-fastest` and `affinity_scope: group`. The first successful egress is reused across eligible destinations until the group is idle for the affinity TTL or selection is forced to change. Applications sharing the listener share that affinity. A destination rule can restrict the eligible members for a particular destination. An exception to the preferred egress leaves the group affinity in place for other destinations.

Destination rules run before ranking. The first matching rule wins. A rule can match `hosts`, `suffixes`, `cidrs`, or `ports`. Host and suffix matching is case insensitive. CIDRs apply to IP literals. When a rule sets `members`, it restricts the request to those explicit members. Use `deny: true` to reject a match. Unmatched requests are denied by default when rules exist. Set `unmatched: allow` explicitly to use the whole approved group for other destinations.

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

Point an application at `http://127.0.0.1:1082/office.pac` or print the script with `ntwire proxy pac --config egress.yaml --group office`. Each script points to a single local group and delegates destination rules to that group. It performs no DNS lookups and includes no direct fallback. Use `default.pac` for the default group. The proxy and PAC listeners need distinct addresses.

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

Set `routing.udp_associate: true` in a SOCKS5 group that has a server advertising native SOCKS UDP in its authenticated grant. Aggregate UDP requires an updated server and a governed SOCKS tunnel without a TCP-only upstream. One eligible egress is chosen for the association, and every datagram is checked against the group's current rules and that member. This allows an association to carry multiple destinations while retaining one source identity. To reach destinations assigned to disjoint member sets, use separate groups. Remote SOCKS UDP framing preserves hostnames for egress-side DNS. The router rejects fragments and pins the sender to the TCP peer's loopback address and declared UDP port, or the first accepted datagram's port when the client supplies zero. The TCP control lifetime and `udp_idle_timeout` bound the relay lifetime.

## Developer verification

Run the focused integration test and benchmark against local origins. The relay case starts a real UDP relay and waits for the client to select that carrier.

```sh
go test ./pkg/client ./pkg/egressrouter ./internal/egressattach ./internal/gui/api -run 'SmartProxy|Attachment'
go test ./pkg/client ./pkg/egressrouter -run '^$' -bench 'BenchmarkSmartProxy' -benchmem
go test -race ./...
```

Compare measurements on the same host, carrier and origin. The benchmark reports setup and echo TTFB percentiles, allocations, and round-trip bytes per second. Bulk throughput, CPU/RSS under sustained concurrent load, and latency under controlled packet loss require a separate representative test run.
