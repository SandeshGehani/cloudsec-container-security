"""Regression checks for bypasses that could otherwise publish an unsafe image."""

import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from evaluate import REQUIRED_STAGES, evaluate
from infra_policy import evaluate_infrastructure


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.policy = json.loads((ROOT / 'policy' / 'gates.json').read_text())
        self.policy_path = self.directory / 'policy.json'
        self.write('policy.json', self.policy)
        self.write('run.json', {'variant': 'hardened', 'stages': {
            stage: {'status': 'ok'} for stage in REQUIRED_STAGES
        }})
        self.write('hadolint.json', [])
        for framework in ('kubernetes', 'terraform'):
            self.write(f'checkov-{framework}.json', {
                'check_type': framework, 'summary': {'parsing_errors': 0},
                'results': {'passed_checks': [
                    {'check_id': rule} for rule in self.policy[f'required_{framework}_checks']
                ], 'failed_checks': [], 'skipped_checks': []},
            })
        self.write('infra-policy.json', {'findings': [], 'kubernetes_documents': 4, 'terraform_deployments': 1})
        self.write('image-inspect.json', [{'Config': {'User': '10001:10001'}, 'Size': 100, 'Id': 'sha256:test'}])
        self.write('trivy.json', {'SchemaVersion': 2, 'ArtifactType': 'container_image', 'Results': []})
        self.write('grype.json', {'matches': [], 'descriptor': {'db': {'built': '2026-11-12T00:00:00Z'}}})
        self.write('sbom.syft.json', {'artifacts': [{'name': 'flask'}]})
        self.write('sbom.cdx.json', {'bomFormat': 'CycloneDX', 'components': [{'name': 'flask'}]})
        self.write('dockle.json', {'summary': {'fatal': 0}, 'details': []})
        self.write('trivy.sarif', {'version': '2.1.0', 'runs': [{}]})
        self.write('trivy-version.json', {'Version': 'test', 'VulnerabilityDB': {'UpdatedAt': '2026-11-12'}})
        self.write('grype-db.json', {'built': '2026-11-12'})

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, name, data):
        (self.directory / name).write_text(json.dumps(data), encoding='utf-8')

    def read(self, name):
        return json.loads((self.directory / name).read_text())

    def evaluate(self):
        return evaluate(self.directory, self.policy_path)

    def test_complete_clean_evidence_passes(self):
        self.assertTrue(self.evaluate()['passed'])

    def test_missing_and_corrupt_reports_block(self):
        (self.directory / 'trivy.json').unlink()
        (self.directory / 'dockle.json').write_text('{broken')
        result = self.evaluate()
        self.assertFalse(result['passed'])
        self.assertGreaterEqual(len(result['errors']), 2)

    def test_scanner_crash_blocks_even_with_clean_report(self):
        run = self.read('run.json')
        run['stages']['grype'] = {'status': 'error', 'error': 'database download failed'}
        self.write('run.json', run)
        self.assertFalse(self.evaluate()['passed'])

    def test_missing_required_check_blocks(self):
        checkov = self.read('checkov-kubernetes.json')
        checkov['results']['passed_checks'].pop()
        self.write('checkov-kubernetes.json', checkov)
        self.assertTrue(self.evaluate()['errors'])

    def test_skipping_required_check_blocks(self):
        checkov = self.read('checkov-kubernetes.json')
        skipped = checkov['results']['passed_checks'].pop()
        checkov['results']['skipped_checks'].append(skipped)
        self.write('checkov-kubernetes.json', checkov)
        self.assertFalse(self.evaluate()['passed'])

    def test_fixable_high_or_critical_blocks_both_scanners(self):
        for tool in ('trivy', 'grype'):
            for severity in ('HIGH', 'CRITICAL'):
                with self.subTest(tool=tool, severity=severity):
                    if tool == 'trivy':
                        report = self.read('trivy.json')
                        report['Results'] = [{'Target': 'image', 'Vulnerabilities': [{
                            'VulnerabilityID': 'CVE-DEMO', 'PkgName': 'flask',
                            'Severity': severity, 'FixedVersion': '3.1.3',
                        }]}]
                    else:
                        self.write('trivy.json', {'SchemaVersion': 2, 'ArtifactType': 'container_image', 'Results': []})
                        report = self.read('grype.json')
                        report['matches'] = [{'artifact': {'name': 'flask'}, 'vulnerability': {
                            'id': 'CVE-DEMO', 'severity': severity,
                            'fix': {'state': 'fixed', 'versions': ['3.1.3']},
                        }}]
                    self.write(f'{tool}.json', report)
                    self.assertFalse(self.evaluate()['passed'])

    def test_unfixed_critical_is_reported(self):
        report = self.read('trivy.json')
        report['Results'] = [{'Target': 'image', 'Vulnerabilities': [{
            'VulnerabilityID': 'CVE-DEMO', 'PkgName': 'flask', 'Severity': 'CRITICAL',
        }]}]
        self.write('trivy.json', report)
        result = self.evaluate()
        self.assertTrue(result['passed'])
        self.assertEqual(result['severity_counts']['trivy']['CRITICAL'], 1)

    def test_secret_blocks(self):
        report = self.read('trivy.json')
        report['Results'] = [{'Target': 'dummy-secret.txt', 'Secrets': [{'RuleID': 'demo'}]}]
        self.write('trivy.json', report)
        self.assertFalse(self.evaluate()['passed'])

    def test_root_or_implicit_user_blocks(self):
        for user in ('', '0', '0:0', 'root', 'root:root'):
            with self.subTest(user=user):
                self.write('image-inspect.json', [{'Config': {'User': user}, 'Size': 100, 'Id': 'sha256:test'}])
                self.assertFalse(self.evaluate()['passed'])

    def test_dockle_fatal_blocks(self):
        self.write('dockle.json', {'summary': {'fatal': 1}, 'details': [
            {'level': 'FATAL', 'code': 'CIS-DI-0001', 'title': 'Root user'}
        ]})
        self.assertFalse(self.evaluate()['passed'])

    def test_empty_dockle_details_are_valid_only_with_zero_fatals(self):
        self.write('dockle.json', {'summary': {'fatal': 0}, 'details': None})
        self.assertTrue(self.evaluate()['passed'])
        self.write('dockle.json', {'summary': {'fatal': 1}, 'details': None})
        self.assertFalse(self.evaluate()['passed'])

    def test_expired_exception_blocks(self):
        self.policy['exceptions'] = [{'tool': 'trivy', 'rule': 'CVE-DEMO', 'subject': 'flask',
                                     'justification': 'Example review', 'review_date': '2000-01-01'}]
        self.write('policy.json', self.policy)
        self.assertTrue(self.evaluate()['errors'])

    def test_hardened_infrastructure_passes(self):
        self.assertEqual(evaluate_infrastructure(ROOT, 'hardened')['findings'], [])

    def test_baseline_infrastructure_fails(self):
        findings = evaluate_infrastructure(ROOT, 'baseline')['findings']
        self.assertEqual({item['id'] for item in findings}, {'PROJECT_NON_ROOT', 'PROJECT_PUBLIC_SERVICE'})
