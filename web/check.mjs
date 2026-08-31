import { readFile, readdir, stat } from "node:fs/promises";
import { resolve, relative, dirname, extname } from "node:path";

const site = resolve(import.meta.dirname);
const failures = [];

async function walk(directory) {
  const entries = await readdir(directory);
  const files = [];
  for (const entry of entries) {
    const target = resolve(directory, entry);
    if ((await stat(target)).isDirectory()) files.push(...await walk(target));
    else files.push(target);
  }
  return files;
}

const files = await walk(site);
const htmlFiles = files.filter((file) => extname(file) === ".html");
const localAssets = new Set(files.map((file) => resolve(file)));

for (const file of htmlFiles) {
  const html = await readFile(file, "utf8");
  const label = relative(site, file);
  if (!/<title>[^<]+<\/title>/.test(html)) failures.push(`${label}: missing title`);
  if (!/<meta name="description" content="[^"]+">/.test(html)) failures.push(`${label}: missing description`);
  if (!/<meta property="og:image" content="https:\/\/ntwire\.io\/assets\/og\.png">/.test(html)) failures.push(`${label}: missing canonical social image`);
  const ids = new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((match) => match[1]));
  for (const match of html.matchAll(/(?:href|src)="([^"]+)"/g)) {
    const value = match[1];
    if (/^(https?:|mailto:|tel:|data:)/.test(value)) continue;
    const [path, fragment] = value.split("#");
    if (fragment && (!path || path === "")) {
      if (!ids.has(fragment)) failures.push(`${label}: missing #${fragment}`);
      continue;
    }
    if (!path || path.startsWith("/")) { if (path.startsWith("/")) failures.push(`${label}: root-relative URL ${value}`); continue; }
    const target = resolve(dirname(file), path);
    if (!localAssets.has(target)) failures.push(`${label}: missing ${value}`);
  }
}

const manifest = JSON.parse(await readFile(resolve(site, "assets/release.json"), "utf8"));
if (!Array.isArray(manifest.assets) || !("releaseUrl" in manifest)) failures.push("assets/release.json: invalid fallback schema");
const chartIndex = await readFile(resolve(site, "charts/index.yaml"), "utf8");
if (!/^apiVersion: v1\nentries: \{\}/.test(chartIndex)) failures.push("charts/index.yaml: invalid Helm repository index");
if ((await readFile(resolve(site, "CNAME"), "utf8")).trim() !== "ntwire.io") failures.push("CNAME must contain ntwire.io");
const siteJS = await readFile(resolve(site, "assets/site.js"), "utf8");
if (siteJS.includes("window.prompt(\"Copy this command:")) failures.push("assets/site.js: installer copy must not open a prompt");
if (!siteJS.includes("function fallbackCopy(text)")) failures.push("assets/site.js: installer copy needs a clipboard fallback");
if (!siteJS.includes("function orderedAssets(assets)") || !siteJS.includes("data-download-sort")) failures.push("assets/site.js: download table needs sortable binary and platform columns");
const siteCSS = await readFile(resolve(site, "assets/site.css"), "utf8");
if (!siteCSS.includes(".install-command-copy{display:flex;width:100%;min-width:0") || !siteCSS.includes("overflow-wrap:anywhere")) failures.push("assets/site.css: installer commands must wrap inside their cards");
if (!siteCSS.includes(".download-sort") || !siteCSS.includes(".download-table th:hover .download-sort span")) failures.push("assets/site.css: download sort controls must appear on hover");
if (failures.length) { console.error(failures.join("\n")); process.exit(1); }
console.log(`Validated ${htmlFiles.length} HTML pages and release manifest.`);
