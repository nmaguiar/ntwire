## Use this tunnel as a SOCKS proxy

This tunnel is an embedded SOCKS4/5 proxy (see `target: socks` and the "SOCKS
proxy tunnels" section in the server's `docs/CONFIGURATION.md`). Once
`ntwire connect` is running, point any SOCKS-aware client at:

- Host: `{{.LocalHost}}`
- Port: `{{.LocalPort}}`
- Type: SOCKS5, with remote/proxy DNS resolution enabled so hostnames are
  resolved on the far side of the tunnel instead of locally -- required for
  any name that only resolves inside the target network.

### curl

```sh
curl --proxy socks5h://{{.LocalHost}}:{{.LocalPort}} https://internal.example/
```

`socks5h`, not `socks5`, is what sends the hostname through the proxy instead
of resolving it first on this machine.

### Browsers

Set the proxy in the browser's network settings to SOCKS5
`{{.LocalHost}}:{{.LocalPort}}` with "Proxy DNS when using SOCKS v5" (Firefox)
or the equivalent remote-DNS option enabled. Chrome can also be launched
directly with the proxy set, in a separate profile so it does not affect your
normal browsing:

```sh
chrome --user-data-dir=/tmp/ntwire-chrome --proxy-server="socks5://{{.LocalHost}}:{{.LocalPort}}"
```

The client status UI's **Open in browser** button on this tunnel does exactly
this for you, in its own isolated profile under `~/.ntwire/browser-profiles/`;
**Reset browser profile** next to it clears that profile if it accumulates
stale cookies or cached credentials.

### Database clients (e.g. DBeaver)

Add a SOCKS proxy to the connection's network/proxy settings: type SOCKS5,
host `{{.LocalHost}}`, port `{{.LocalPort}}`.

For Oracle drivers specifically, set these driver properties instead of the
generic proxy settings:

- `oracle.net.socksProxyHost` = `{{.LocalHost}}`
- `oracle.net.socksProxyPort` = `{{.LocalPort}}`
- `oracle.net.socksRemoteDNS` = `true`

### kubectl and other tools without native SOCKS support

Go's HTTP client honors the `HTTPS_PROXY` environment variable, including a
`socks5://` value, so tools like `kubectl` still work through this tunnel
without any SOCKS-specific configuration:

```sh
HTTPS_PROXY=socks5://{{.LocalHost}}:{{.LocalPort}} kubectl get nodes
```

This still talks TLS end to end to the real API server, so normal
certificate verification applies -- unlike a direct forwarding tunnel to the
API server, no `--tls-server-name` override is needed here.

### Automatic Proxy Configuration (PAC)

Instead of setting manual proxy settings on every app, configure your operating system or browser with the Proxy Auto-Configuration (.pac) URL.

- **Desktop (macOS / Windows / Linux / Browsers):**
  - Use PAC URL: `{{.PACURL}}`
  - **macOS:** System Settings → Network → (Select Interface) → Details → Proxies → Enable **Automatic Proxy Configuration** → enter the PAC URL.
  - **Windows:** Settings → Network & Internet → Proxy → Automatic proxy setup → enable **Use setup script** → enter the PAC URL.
  - **Firefox:** Settings → General → Network Settings → **Automatic proxy configuration URL** → enter the PAC URL.

- **iOS / iPadOS (with official WireGuard app connected):**
  - Use PAC URL: `{{.PACURLiOS}}`
  - **iOS:** Settings → Wi-Fi (or Cellular) → tap your network's **(i)** info icon → **Configure Proxy** → select **Automatic** → enter the iOS PAC URL.
  - Safari and iOS apps will route internal domains (`*.svc`, `*.cluster.local`, `*.local`, `10.0.0.0/8`, etc.) through the WireGuard SOCKS proxy at `100.64.0.1:{{.VirtualPort}}` and access external internet sites directly.

