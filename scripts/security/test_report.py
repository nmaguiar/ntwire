import json
from pathlib import Path
import tempfile
import unittest

from report import parse, render
from verify_reports import targets, verify


class ReportTest(unittest.TestCase):
    def test_trivy_findings_and_empty(self):
        data = {'SchemaVersion': 2, 'Results': [{'Vulnerabilities': [{'VulnerabilityID': 'CVE-1', 'Severity': 'HIGH', 'PkgName': 'pkg'}]}]}
        self.assertEqual(parse('image', json.dumps(data))[0][:3], ('CVE-1', 'HIGH', 'pkg'))
        self.assertEqual(parse('image', json.dumps({'SchemaVersion': 2, 'Results': []})), [])
        self.assertEqual(parse('image', json.dumps({'SchemaVersion': 2, 'ArtifactName': 'example/image'})), [])

    def test_go_findings_and_empty(self):
        config = {'config': {'protocol_version': 'v1.0.0'}}
        finding = {'finding': {'osv': 'GO-1'}}
        osv = {'osv': {'id': 'GO-1', 'affected': [{'module': {'path': 'example.org/a'}}]}}
        self.assertEqual(parse('binary', json.dumps(config)), [])
        self.assertEqual(parse('binary', '\n'.join(map(json.dumps, [config, osv, finding])))[0][:3], ('GO-1', 'UNKNOWN', 'example.org/a'))
        with self.assertRaises(ValueError):
            parse('binary', '\n'.join(map(json.dumps, [config, finding])))

    def test_bad_scans_rejected(self):
        for kind, raw in [('image', '{}'), ('image', 'bad'), ('binary', ''), ('binary', '{}'), ('binary', '{')]:
            with self.subTest(kind=kind, raw=raw), self.assertRaises(ValueError):
                parse(kind, raw)

    def test_render_and_complete_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            commit = 'a' * 40
            for name in targets():
                kind = 'image' if name.startswith('image-') else 'binary'
                raw = json.dumps({'SchemaVersion': 2, 'Results': []} if kind == 'image' else {'config': {'protocol_version': 'v1.0.0'}})
                render(kind, raw, name, 'linux/amd64', 'sha256:123', commit, path)
            verify(path, commit)
            (path / (next(iter(targets())) + '.svg')).unlink()
            with self.assertRaises(ValueError):
                verify(path, commit)

if __name__ == '__main__':
    unittest.main()
