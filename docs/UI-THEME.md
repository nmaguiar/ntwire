# ntwire UI Theme

ntwire uses a crisp, operations-focused theme that should feel calm during normal tunnel use and clear during incident response. The local status UI supports both light and dark modes through CSS custom properties and the user's `prefers-color-scheme` setting.

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

Light mode should feel airy and readable, with enough brand color to make actions obvious but not noisy.

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

Dark mode should reduce glare while keeping tunnel metadata legible for long-running monitoring sessions.

## Component Guidance

- Use a single hero card for the connection overview and a responsive card grid for tunnels.
- Present tunnel addresses in monospace chips so users can copy and distinguish them quickly.
- Keep forms inline where possible, with clear labels and a primary action button.
- Use status badges for connected/disconnected states and preserve text equivalents for assistive technology.
- Avoid relying on color alone; pair badges and errors with explicit text.
