#!/usr/bin/env python3
"""Validate scanner output and render a self-contained Markdown report and SVG badge."""
import argparse
import datetime
import html
import json
from pathlib import Path
import re

LEVELS = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')

def parse(kind, raw):
    if kind == 'image':
        data = json.loads(raw)
        if data.get('SchemaVersion') != 2 or not isinstance(data.get('Results', []), list) or ('Results' not in data and not data.get('ArtifactName')):
            raise ValueError('invalid Trivy report')
        findings = []
        for result in data.get('Results', []):
            for v in result.get('Vulnerabilities') or []:
                if not v.get('VulnerabilityID'):
                    raise ValueError('missing vulnerability ID')
                findings.append((v['VulnerabilityID'], v.get('Severity', 'UNKNOWN').upper(), v.get('PkgName', ''), v.get('InstalledVersion', ''), v.get('FixedVersion', ''), v.get('PrimaryURL', '')))
        return findings
    decoder = json.JSONDecoder()
    messages = []
    while raw.strip():
        raw = raw.lstrip()
        obj, end = decoder.raw_decode(raw)
        if not isinstance(obj, dict) or len(obj) != 1:
            raise ValueError('invalid govulncheck message')
        messages.append(obj)
        raw = raw[end:]
    if not messages or 'config' not in messages[0] or not messages[0]['config'].get('protocol_version'):
        raise ValueError('missing govulncheck config')
    osv = {m['osv']['id']: m['osv'] for m in messages if 'osv' in m}
    ids = {m['finding']['osv'] for m in messages if 'finding' in m}
    if ids - osv.keys():
        raise ValueError('missing advisory details')
    return [(i, 'UNKNOWN', ', '.join(a.get('module', {}).get('path', '') for a in osv[i].get('affected', [])), '', '', 'https://pkg.go.dev/vuln/' + i) for i in sorted(ids)]

def render(kind, raw, target, platform, identity, commit, output):
    findings = parse(kind, raw)
    counts = {level: 0 for level in LEVELS}
    for _, severity, *_ in findings:
        counts[severity if severity in counts else 'UNKNOWN'] += 1
    now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    def cell(v):
        return str(v).replace('|', '&#124;').replace('\n', ' ')
    lines = [f'# {target} — {platform}', '', f'- Scanned: {now}', f'- Source commit: `{commit}`', f'- Artifact: `{identity}`', f'- Scanner: {"Trivy" if kind == "image" else "govulncheck (binary mode)"}', '', ' | '.join(f'{k}: {v}' for k, v in counts.items()), '']
    if kind == 'binary':
        lines += ['Go vulnerability reports do not assign severity here; findings are counted as unknown. Binary analysis can include unreachable code.', '']
    if findings:
        lines += ['| Advisory | Severity | Package | Installed | Fixed |', '| --- | --- | --- | --- | --- |']
        for ident, severity, package, installed, fixed, url in findings:
            advisory = f'[{cell(ident)}]({url})' if url.startswith('https://') else cell(ident)
            lines.append(f'| {advisory} | {cell(severity)} | {cell(package)} | {cell(installed)} | {cell(fixed)} |')
    else:
        lines.append('No vulnerabilities reported.')
    lines += ['', '<details><summary>Full scanner output</summary>', '', '```json', raw.strip(), '```', '</details>']
    output.mkdir(parents=True, exist_ok=True)
    (output / (target + '.md')).write_text('\n'.join(lines) + '\n')
    label = f'{len(findings)} findings'
    color = '#d73a49' if counts['CRITICAL'] or counts['HIGH'] else ('#dfb317' if findings else '#4c1')
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="180" height="20" role="img" aria-label="{html.escape(target)}: {label}"><rect width="180" height="20" rx="3" fill="#555"/><path fill="{color}" d="M100 0h77a3 3 0 0 1 3 3v14a3 3 0 0 1-3 3h-77z"/><g fill="#fff" text-anchor="middle" font-family="Verdana,sans-serif" font-size="10"><text x="50" y="14">security scan</text><text x="140" y="14">{label}</text></g></svg>\n'
    (output / (target + '.svg')).write_text(svg)

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    for name in ('kind', 'input', 'target', 'platform', 'identity', 'commit', 'output'):
        p.add_argument('--' + name, required=True)
    a = p.parse_args()
    if a.kind not in ('image', 'binary') or not re.fullmatch(r'[a-z0-9-]+', a.target) or not re.fullmatch(r'[0-9a-f]{40}', a.commit):
        p.error('invalid metadata')
    render(a.kind, Path(a.input).read_text(), a.target, a.platform, a.identity, a.commit, Path(a.output))
