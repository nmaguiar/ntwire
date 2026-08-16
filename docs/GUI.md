# ntwire-gui

`ntwire-gui` is a tray/menu-bar client: the same functionality as `ntwire
connect`, for one or more server profiles held and connected
simultaneously, run from a system tray icon instead of a terminal. It
embeds `pkg/client` directly rather than shelling out to `ntwire`, and
shares its command-line option definitions with `cmd/ntwire` via
`pkg/clientopts`, so the two can't drift apart.

## Two processes, one binary

`ntwire-gui` re-executes itself with a hidden `--window` flag to host its
settings UI, rather than doing everything in one process:

```
core process                         settings-window process
  main thread: tray event loop         main thread: window (native or browser)
  connection manager, N profiles  <->  HTTP client of the core's API
  loopback HTTP+SSE settings API
```

This exists because the tray library's platform backends and a native
window's event loop can't safely share one thread's run loop (see
`internal/gui/tray`'s package doc for the empirical reason this was
settled, not assumed). It also means:

- The tray keeps running, and keeps every tunnel up, independent of
  whatever the settings window is doing -- closing it, crashing it, or
  never opening it at all.
- The settings window is just an HTTP+SSE client of a token-authenticated
  loopback API (`internal/gui/api`), the same pattern `pkg/client`'s own
  local status dashboard already uses. A browser pointed at that API's URL
  works identically to the bundled window.

## Two build modes

| | Tray | Settings window |
| --- | --- | --- |
| `go build ./cmd/ntwire-gui` (default) | Native (`NSStatusItem` / DBus `StatusNotifierItem` / `Shell_NotifyIcon`) | Opens in the default browser |
| `go build -tags gui ./cmd/ntwire-gui` | Native, same as above | Native webview (`WKWebView` / WebView2 / WebKitGTK) |

The default build needs no C toolchain on Linux or Windows at all;
`internal/gui/tray`'s Linux backend is pure Go over D-Bus, verified by a
`CGO_ENABLED=0` cross-build in CI. It **does** need cgo on macOS regardless
of the `gui` tag -- the tray itself is Cocoa there. `-tags gui` additionally
needs `github.com/webview/webview_go`'s toolchain: a C++ compiler
everywhere, plus `webkit2gtk-4.0`'s dev package on Linux (unverified
against current distro package names; if that `.pc` file isn't installed,
build without `-tags gui` and rely on the browser fallback). `ojob
tasks.yaml op=gui` builds the default (untagged) mode for the host
platform.

## Profiles and storage

`ntwire-gui` owns its own store, `~/.ntwire/gui.yaml`, holding N server
profiles (a superset of the CLI's single-server `client.Settings`). On
first run, if a CLI `~/.ntwire/config.yaml` exists, it seeds one imported
profile from it -- and after that, never writes `config.yaml` again;
`ntwire connect` remains its only writer. Each profile gets its own status
file under `~/.ntwire/gui/`, so a GUI-managed connection can never delete
or overwrite a CLI session's status file.

For an OIDC provider that requires a client secret, open a profile's **SSO
(advanced)** section and enter it as **OIDC client secret**. The secret is
stored only in that profile's `gui.yaml` (which ntwire-gui writes with mode
`0600`) and is sent only to the OIDC token endpoint. It is write-only in the
settings UI and API: after saving, it is never returned or displayed again;
leave the field blank while editing a profile to retain the saved value. A
profile secret takes precedence over `NTWIRE_OIDC_CLIENT_SECRET`; the
environment variable remains the CLI-compatible fallback when no GUI secret
is saved.

## Autostart and single instance

Toggling "Start at login" in the tray registers a per-OS login item via
`internal/gui/autostart`: a
`LaunchAgent` plist on macOS, a `.desktop` entry under
`~/.config/autostart` on Linux, or a `HKCU\...\Run` value on Windows. None
of these take effect until the next login -- there is no attempt to
register with the running session manager immediately.

A login-triggered launch passes `--autostart`, which is what makes a
profile with `connect_on_start: true` actually connect; an interactive
launch does not auto-connect anything by itself. Launching a second
instance against the same `gui.yaml` detects the first one (via a lock
file holding its loopback URL, verified live with an authenticated probe,
not just trusted on sight) and raises its settings window instead of
starting a second connection manager.

## Current limitations

- **Unsigned and unnotarized.** macOS users hit Gatekeeper's "unidentified
  developer" warning (right-click -> Open works around it); Windows users
  hit SmartScreen. Both need a paid developer account this project doesn't
  have yet, and are tracked as follow-up work, not planned here.
- **Changing a running tunnel's port** is a settings-window action only
  (`PUT /api/profiles/{id}/tunnels/{name}`, matching `ntwire port`) --
  there is no in-tray text input to collect a new port number.
- **Linux tray visibility** depends on the desktop environment hosting a
  `StatusNotifierItem` tray at all; GNOME needs an extension for this
  (a `fyne.io/systray` constraint, not one this project can work around).
- **Notifications** are not implemented; the tray icon's aggregate state
  (all/some/none connected, or needs attention) is the only ambient signal
  today.

## CLI parity

| `ntwire` | `ntwire-gui` |
| --- | --- |
| `connect` | A profile's Connect action; every flag `pkg/clientopts` exposes as non-hidden appears in the settings form |
| `list` | "Preview tunnels" (`POST /api/profiles/{id}/probe`) |
| `disconnect` | A profile's Disconnect action |
| `port` | Settings window's live per-tunnel port change |
| `logout` | "Clear SSO tokens" |
| `keygen` | Settings window's "Generate new identity…" |
| `status` | Tray labels and the settings window's live profile list, both fed by the typed `Connection.State()` snapshot and lifecycle events |

## Live connection state

The settings API exposes a profile's `connection` only while it has a live
client handle. This is a typed `client.ConnectionState` snapshot, refreshed
on each API read and manager event. It carries the connection and
authentication method, actual tunnel listeners, machine-readable and display
transport state, reconnect attempt/error/retry timing, session expiry,
latency, reconnection count, and non-secret security state (negotiated
transport capabilities, explicit insecure-TLS use, and listener bind
address). The GUI does not parse client logs for any connection state.
