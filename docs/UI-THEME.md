---
title: ntwire UI Theme
description: Visual theme and styling reference for the ntwire web UI
type: reference
---

# ntwire UI Theme

ntwire uses a crisp, operations-focused theme that should feel calm during normal tunnel use and clear during incident response. The local status UI supports both light and dark modes through CSS custom properties and the user's `prefers-color-scheme` setting.

This reference is authoritative for the **client status UI**
(`pkg/client/webui`). Two other surfaces are separately templated and mostly,
but not exactly, share this palette: the server operator dashboard
(`pkg/server/webui`) and the GUI settings window (`internal/gui/webui`). Where
they diverge from the tables below, or from each other, it's called out
inline rather than assumed.

## Design Goals

- **Immediate status recognition:** connection state, tunnel address, traffic volume, and active connections are visually grouped for fast scanning.
- **Appealing but restrained:** soft gradients, rounded cards, and subtle shadows add polish without hiding operational data.
- **Accessible contrast:** both palettes target high contrast for text, controls, status messages, and code-like addresses.
- **Responsive local console:** the layout works on narrow laptop browser windows and larger desktop displays.

## Light Mode Palette

| Token | Value | Usage |
| --- | --- | --- |
| `--bg` | `#f7f9fc` | Page background |
| `--panel` | `#ffffff` | Cards and controls |
| `--text` | `#162033` | Primary copy |
| `--muted` | `#607089` | Secondary copy and labels |
| `--brand` | `#246bfe` | Buttons and key highlights |
| `--brand-strong` | `#174fc5` | Button hover/focus |
| `--accent` | `#10a37f` | Connected indicators |
| `--danger` | `#c2410c` | Error/status messages |
| `--border` | `#d9e2f1` | Card and input borders |
| `--panel-2` | `#eef4ff` | Secondary surfaces (badges, stat tiles, code blocks) — defined identically in all three surfaces |

Light mode should feel airy and readable, with enough brand color to make actions obvious but not noisy.

The server dashboard does not define `--brand-strong`: its own reconnect
banner has no hover-styled button, just a plain `#fff` background with
`--danger`-colored text. The GUI settings window additionally defines
`--danger-strong` (`#9a3412` light / `#fdba74` dark, used the way
`--brand-strong` is used for `--brand`), which appears nowhere in the client
status UI or the server dashboard.

## Dark Mode Palette

| Token | Value | Usage |
| --- | --- | --- |
| `--bg` | `#0b1120` | Page background |
| `--panel` | `#111a2e` | Cards and controls |
| `--text` | `#edf4ff` | Primary copy |
| `--muted` | `#9fb0ca` | Secondary copy and labels |
| `--brand` | `#79a7ff` | Buttons and key highlights |
| `--brand-strong` | `#a9c5ff` | Button hover/focus |
| `--accent` | `#4ade80` | Connected indicators |
| `--danger` | `#fb923c` | Error/status messages |
| `--border` | `#263753` | Card and input borders |
| `--panel-2` | `#15223a` | Secondary surfaces — see the light-mode row above |

Dark mode should reduce glare while keeping tunnel metadata legible for long-running monitoring sessions.

## Component Guidance

The following apply to the client status UI (`pkg/client/webui`), the primary
subject of this doc. The server dashboard shares the card/grid/badge visual
language but has no collapsible `<details>` cards, no `localStorage` use, and
no Markdown rendering. The GUI settings window has `<details>` cards but does
not persist their open/closed state to `localStorage`.

- Use a single hero card for the connection overview and a responsive card grid for tunnels.
- Present tunnel addresses in monospace chips so users can copy and distinguish them quickly.
- Keep forms inline where possible, with clear labels and a primary action button.
- Use status badges for connected/disconnected states and preserve text equivalents for assistive technology.
- Avoid relying on color alone; pair badges and errors with explicit text.
- Make each tunnel card a `<details>`/`<summary>` section so long cards can be folded away. The status UI rebuilds its cards on every poll, so which sections are collapsed lives in `localStorage`, not in the DOM.
- Reveal copy-to-clipboard buttons on hover and on keyboard focus, and keep them visible where hover does not exist (`@media (hover:none)`). They are icon-only, so give each an `aria-label`, and confirm the copy on the button itself rather than in the shared status line.
- Render server-supplied instruction Markdown as DOM nodes built from the client's parsed block tree; never assign it as markup, and only ever link to absolute `http(s)` targets.
