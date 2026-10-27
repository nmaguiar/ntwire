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

See [GUI.md](GUI.md) for build modes, profile storage, autostart, and the
Windows GUI-subsystem build command that avoids a command-prompt window.

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

## Recovery after network changes

Both `ntwire` and `ntwire-gui` use the same recovery engine for established
connections. Switching Wi-Fi networks or moving between Ethernet and Wi-Fi
can interrupt traffic while the operating system installs the new route.
Control-plane requests time out after 15 seconds, including stalled response
bodies, so renewal can enter its automatic retry loop. Retries back off from
1 second to a maximum of 1 minute while keeping local tunnel listeners open.

Client WebSocket carriers send native ping frames every 15 seconds and allow
10 seconds for a pong. An unresponsive carrier is closed and automatically
redialed, even when the tunnel is idle. Redial retries use jittered backoff
capped at 30 seconds. These are detection and retry intervals, not a guarantee
of uninterrupted application sessions or a fixed total recovery time.
Multipath can select another available path; explicit `direct-udp` connections
have no WebSocket fallback if the new network blocks UDP.

An initial connection failure is different: the CLI exits and the GUI profile
requires another Connect attempt. Expired or revoked login credentials may
also require user action. Local listeners explicitly bound to an address of
the old interface remain bound to that address; prefer loopback for local use.

## Related guides

- [CONNECTING.md](CONNECTING.md) — connecting to a direct server or relay.
- [CONFIGURATION.md](CONFIGURATION.md) — client proxy/transport settings and server-issued tunnel instructions.
- [NATIVE-WIREGUARD.md](NATIVE-WIREGUARD.md) — official WireGuard clients.
- [IOS.md](IOS.md) — archived native iOS/iPadOS client status.

## PuTTY private keys

Select an OpenSSH/PEM key or a PuTTY PPK v2/v3 private key with `-i`,
`identity_file`, or the GUI key picker. Format detection uses file contents,
regardless of the filename extension. Encrypted PPK keys use the existing
passphrase prompt; the CLI requires a terminal. Default identity discovery
is unchanged; select PPK files explicitly. No conversion file is created.

## Updating the client

Use `ntwire update --check` to check a signed stable release, `ntwire update` for
an interactive installation, or `ntwire update --yes` for unattended installation.
The CLI never checks automatically or prompts for elevation. See
[Client updates](UPDATES.md) for supported locations, verification and recovery.

## Private-key formats and conversion

SSH identities are detected by content, regardless of filename. ntwire accepts
OpenSSH private keys, traditional PEM, unencrypted PKCS#8 PEM, encrypted
PKCS#8 PEM (`ENCRYPTED PRIVATE KEY`), and PuTTY PPK v2/v3. Encrypted PKCS#8
uses PKCS#5 v2 PBES2 with PBKDF2 or scrypt and AES-CBC or 3DES-CBC; legacy
PKCS#5 v1 schemes are unsupported. To keep imported files from exhausting
client resources, PBKDF2 is limited to 1,000,000 iterations and scrypt is
limited to 256 MiB of memory and 4,194,304 `N*r*p` work units. RSA, ECDSA and
Ed25519 keys are supported. Encrypted keys require a passphrase. Raw DER,
PKCS#12, SSH-agent identities and hardware-backed keys are not directly
supported.

Keep the original file. Run these commands in a private directory, choose a
new output name that does not already exist, and enter passwords interactively.
The shell's `umask` protects newly created files; the examples do not print
private key material. OpenSSL may require its legacy provider for old PKCS#12
files.

```sh
umask 077
# Extract the private key, choosing a new output encryption password:
openssl pkcs12 -in identity.p12 -nocerts -out identity-from-p12.pem
# Convert a DER PKCS#8 private key to encrypted PEM:
openssl pkey -inform DER -in identity.der -aes256 -out identity-from-der.pem
```

For an SSH2/RFC 4716 private-key export accepted by your version of OpenSSH,
import it to a new file and then protect the resulting key with a passphrase:

```sh
umask 077
ssh-keygen -i -m RFC4716 -f ssh2-private-key > identity-from-ssh2
ssh-keygen -p -f identity-from-ssh2
```

OpenSSH's SSH2 import supports only certain private-key encodings and key types;
if it rejects your export, use the exporting application's private-key conversion
feature or ask the administrator for a supported private key. RFC 4716 commonly
contains public keys: a public key or certificate alone cannot be converted into
its private key.

Verify the identity against the administrator-authorized public key before use.
For an OpenSSH private key, `ssh-keygen -y -f identity-from-ssh2` produces its
public key; compare its `ssh-keygen -lf` fingerprint with the authorized key's
fingerprint. For PKCS#8, use a tool that can derive an SSH public key from the
specific key type, or ask the administrator to compare the derived public key.
For PEM keys OpenSSL can extract the public component with
`openssl pkey -in identity-from-p12.pem -pubout -out public.pem`; share only
public material, never the private key or passphrase.
