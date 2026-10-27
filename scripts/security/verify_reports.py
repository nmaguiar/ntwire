#!/usr/bin/env python3
"""Reject incomplete or mixed-revision report sets before publication."""
from pathlib import Path
import sys


def targets():
    result = {f'image-{name}-linux-{arch}' for name in ('ntwire-client', 'ntwire-server', 'ntwire-relay') for arch in ('amd64', 'arm64')}
    result |= {f'binary-{name}-{os}-{arch}' for name in ('ntwire', 'ntwire-server', 'ntwire-relay', 'ntwire-gui') for os in ('linux', 'windows', 'darwin') for arch in ('amd64', 'arm64') if not (name == 'ntwire-gui' and os == 'darwin' and arch == 'amd64')}
    return result


def verify(directory, commit):
    expected = {name + ext for name in targets() for ext in ('.md', '.svg')}
    actual = {p.name for p in directory.iterdir() if p.is_file()}
    if actual != expected:
        raise ValueError(f'incomplete or unexpected reports: missing={sorted(expected - actual)}, extra={sorted(actual - expected)}')
    for name in targets():
        if f'Source commit: `{commit}`' not in (directory / (name + '.md')).read_text():
            raise ValueError(f'wrong source commit: {name}')
        if '<svg ' not in (directory / (name + '.svg')).read_text():
            raise ValueError(f'invalid badge: {name}')

if __name__ == '__main__':
    verify(Path(sys.argv[1]), sys.argv[2])
