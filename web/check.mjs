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
if ((await readFile(resolve(site, "CNAME"), "utf8")).trim() !== "ntwire.io") failures.push("CNAME must contain ntwire.io");
if (failures.length) { console.error(failures.join("\n")); process.exit(1); }
console.log(`Validated ${htmlFiles.length} HTML pages and release manifest.`);
