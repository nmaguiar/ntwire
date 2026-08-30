# Client guide

This guide covers the `ntwire` command-line client, its local state, the GUI,
and SSO. For a first connection or an official WireGuard client, start with
[CONNECTING.md](CONNECTING.md).

## Commands

| Command | Behavior |
| --- | --- |
| `ntwire keygen [-o path]` | Writes a PKCS#8 Ed25519 private key and an OpenSSH `.pub` key. The default private key is `~/.ntwire/id_ed25519`. |
| `ntwire list [-i key \| --sso] [--json] URL` | Authenticates once and prints server grants. Without `-i` or `identity_file`, it uses `~/.ntwire/id_ed25519` if present, then the first conventional key in `~/.ssh`, or falls back to SSO when advertised. `--json` is machine-readable. Do not add a trailing `/` to `URL`. |
| `ntwire connect [-i key \| --sso] URL [--port name=15432] [--websocket] [--bind address]` | Starts local listeners, renews the session, and prints a token-protected status URL. A tunnel's `local_port`/`local_host` are preferred when available; otherwise a free port and `127.0.0.1` are used. `--port name=local-port` or `--port name=host:local-port` is a client-side override. `--websocket` selects the fallback transport; `--bind` is advanced and changes the exposure of the listener. |
| `ntwire status [--json]` | Shows the running connection's tunnels, transport, and expiry. |
| `ntwire disconnect` | Stops the connection in this state directory. |
| `ntwire port name=15432` | Replaces a running tunnel's local listener; the status UI offers the same action. |
| `ntwire logout URL` | Clears cached SSO credentials for a server. |
| `ntwire version` | Prints the build version. |

Use an `https://` URL. On first use of a self-signed server, confirm its
fingerprint; it is then stored in `~/.ntwire/known_servers`. See
[SECURITY.md](SECURITY.md#tls-trust-model-and-avoiding-repeated-re-trust-prompts)
for stable certificate handling.

Encrypted private keys prompt for their passphrase on a terminal. A
non-interactive invocation without a terminal fails instead of waiting.

`-h`/`--help` uses color and UTF-8 on capable terminals, and automatically
falls back to plain ASCII when piped, redirected, or `NO_COLOR` is set. Use
`--no-color` to disable color explicitly; see [LOGGING.md](LOGGING.md).

## Local dashboard and settings

`connect` prints a token-protected local status URL. Its dashboard links to a
separate, token-protected settings page for `~/.ntwire/config.yaml`. Settings
changes apply to the next `ntwire connect`, not the running connection.

## GUI client

`ntwire-gui` is a tray/menu-bar client for holding and connecting several
server profiles:

```sh
go build -o bin/ntwire-gui ./cmd/ntwire-gui
./bin/ntwire-gui
```

See [GUI.md](GUI.md) for build modes, profile storage, and autostart.

On a first launch with no saved connection, ntwire-gui opens a short setup
page automatically. Paste the `https://` server or relay URL supplied by the
administrator and it connects immediately. If the server offers OIDC, the
normal browser sign-in starts; otherwise the page asks you to choose the SSH
private key the administrator authorized. The tray's **Add connection…** item
opens the same page later. After connecting it opens the local dashboard's
Portal tab, which falls back to the target list when no Portal is available.
Selected identity files are copied into ntwire-gui's private profile directory
because browser file pickers do not expose a source pathname to the page.

## SSO login

When a server advertises OIDC issuers, `connect` and `list` use SSO by default
if no SSH key is found. Pass `--sso` to force it, and `--provider name` when
more than one issuer is available. The default is browser-based Authorization
Code + PKCE with a loopback redirect; `--no-browser` (or no available browser)
uses OAuth device flow instead.

Reusable credentials are stored in the native desktop credential store
(macOS Keychain, Windows Credential Manager, or Secret-Service-compatible
Linux keyring). If unavailable, ntwire uses mode-`0600`
`~/.ntwire/tokens.json`; existing file entries migrate only after a verified
native write. `ntwire logout` clears the local credential. See
[OIDC-SETUP.md](OIDC-SETUP.md) for provider registration and
[SECURITY.md](SECURITY.md) for the token model.

## Related guides

- [CONNECTING.md](CONNECTING.md) — connecting to a direct server or relay.
- [CONFIGURATION.md](CONFIGURATION.md) — client proxy/transport settings and server-issued tunnel instructions.
- [NATIVE-WIREGUARD.md](NATIVE-WIREGUARD.md) — official WireGuard clients.
- [IOS.md](IOS.md) — archived native iOS/iPadOS client status.
