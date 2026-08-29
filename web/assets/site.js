(() => {
  const root = document.documentElement;
  const savedTheme = localStorage.getItem("ntwire-theme");
  if (savedTheme && savedTheme !== "system") root.dataset.theme = savedTheme;
  const theme = document.querySelector("[data-theme-toggle]");
  const labels = { light: "Light", dark: "Dark", system: "System" };
  function currentTheme() { return localStorage.getItem("ntwire-theme") || "system"; }
  function renderTheme() { if (theme) theme.textContent = `Theme: ${labels[currentTheme()]}`; }
  theme?.addEventListener("click", () => { const next = { system: "light", light: "dark", dark: "system" }[currentTheme()]; localStorage.setItem("ntwire-theme", next); if (next === "system") delete root.dataset.theme; else root.dataset.theme = next; renderTheme(); });
  renderTheme();
  function fallbackCopy(text) {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.setAttribute("readonly", "");
    textarea.style.cssText = "position:fixed;left:0;top:0;opacity:0";
    document.body.append(textarea);
    textarea.focus();
    textarea.select();
    textarea.setSelectionRange(0, textarea.value.length);
    let copied = false;
    try { copied = document.execCommand("copy"); } catch { /* Clipboard access is unavailable. */ }
    textarea.remove();
    return copied;
  }
  document.querySelectorAll(".install-command code").forEach((code) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "install-command-copy";
    button.textContent = code.textContent;
    button.setAttribute("aria-label", `Copy command: ${code.textContent}`);
    button.addEventListener("click", async () => {
      let copied = false;
      try {
        await navigator.clipboard.writeText(code.textContent);
        copied = true;
      } catch { copied = fallbackCopy(code.textContent); }
      button.classList.toggle("copied", copied);
      button.classList.toggle("copy-failed", !copied);
      button.setAttribute("aria-label", copied ? "Copied command" : "Unable to copy command");
      setTimeout(() => {
        button.classList.remove("copied", "copy-failed");
        button.setAttribute("aria-label", `Copy command: ${code.textContent}`);
      }, 1600);
    });
    code.replaceWith(button);
  });
  const navToggle = document.querySelector("[data-nav-toggle]");
  const nav = document.querySelector("[data-nav]");
  navToggle?.addEventListener("click", () => { const open = nav.classList.toggle("open"); navToggle.setAttribute("aria-expanded", String(open)); });
  const platforms = { darwin: "macOS", windows: "Windows", linux: "Linux" };
  function platform() { const ua = navigator.userAgent.toLowerCase(); if (/mac|iphone|ipad/.test(ua)) return "darwin"; if (/win/.test(ua)) return "windows"; if (/linux|x11/.test(ua)) return "linux"; return null; }
  function architecture() { const ua = navigator.userAgent.toLowerCase(); return /arm64|aarch64/.test(ua) ? "arm64" : "amd64"; }
  function bytes(size) { if (!size) return ""; const units = ["B", "KB", "MB", "GB"]; let i = 0, n = size; while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; } return `${n.toFixed(i ? 1 : 0)} ${units[i]}`; }
  function assetLabel(asset) { return `${platforms[asset.os] || asset.os} · ${asset.arch === "amd64" ? "Intel/AMD" : "Apple silicon / ARM"}`; }
  function binary(asset) { return asset.binary || "ntwire-gui"; }
  async function releases() {
    const targets = document.querySelectorAll("[data-recommended-download], [data-download-list], [data-release-version]");
    if (!targets.length) return;
    try {
      const response = await fetch(`${root.dataset.assetRoot || ""}assets/release.json`, { cache: "no-store" });
      if (!response.ok) throw new Error("release manifest unavailable");
      const data = await response.json();
      const assets = Array.isArray(data.assets) ? data.assets : [];
      document.querySelectorAll("[data-release-version]").forEach((el) => { el.textContent = data.version ? `Latest: ${data.version}` : "Latest release"; });
      document.querySelectorAll("[data-release-url]").forEach((el) => { el.href = data.releaseUrl || "https://github.com/nmaguiar/ntwire/releases/latest"; });
      const os = platform(), arch = architecture();
      let suggested = assets.find((asset) => binary(asset) === "ntwire-gui" && asset.os === os && asset.arch === arch);
      if (!suggested && os === "darwin") suggested = assets.find((asset) => binary(asset) === "ntwire-gui" && asset.os === "darwin" && asset.arch === "arm64");
      document.querySelectorAll("[data-recommended-download]").forEach((el) => { if (!suggested) { el.href = data.releaseUrl || "https://github.com/nmaguiar/ntwire/releases/latest"; el.textContent = "View downloads on GitHub"; return; } el.href = suggested.url; el.textContent = `Download ntwire-gui for ${assetLabel(suggested)}`; });
      document.querySelectorAll("[data-recommendation-copy]").forEach((el) => { el.textContent = suggested ? `Recommended for this device: ${assetLabel(suggested)}${data.version ? ` · ${data.version}` : ""}.` : "Choose a download for your device."; });
      document.querySelectorAll("[data-download-list]").forEach((list) => {
        list.replaceChildren();
        if (!assets.length) { list.innerHTML = `<tr><td colspan="4">A release has not been published yet. <a href="${data.releaseUrl || "https://github.com/nmaguiar/ntwire/releases/latest"}">View releases on GitHub</a>.</td></tr>`; return; }
        assets.sort((a, b) => `${binary(a)}-${a.os}-${a.arch}`.localeCompare(`${binary(b)}-${b.os}-${b.arch}`)).forEach((asset) => { const row = document.createElement("tr"); const name = document.createElement("td"); name.textContent = binary(asset); const platformCell = document.createElement("td"); platformCell.textContent = assetLabel(asset); const size = document.createElement("td"); size.textContent = bytes(asset.size); const linkCell = document.createElement("td"); const link = document.createElement("a"); link.href = asset.url; link.className = "button small"; link.textContent = "Download"; linkCell.append(link); row.append(name, platformCell, size, linkCell); list.append(row); });
      });
      document.querySelectorAll("[data-checksum-url]").forEach((el) => { if (data.checksumUrl) { el.href = data.checksumUrl; el.hidden = false; } });
    } catch { document.querySelectorAll("[data-recommendation-copy]").forEach((el) => { el.textContent = "Open the latest GitHub release to choose your download."; }); }
  }
  releases();
})();
