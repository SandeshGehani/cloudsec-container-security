"""Evaluate complete scan evidence and fail closed on missing or invalid reports."""

import argparse
from collections import Counter
from datetime import date
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_STAGES = (
    'hadolint', 'checkov-kubernetes', 'checkov-terraform', 'infra-policy',
    'build', 'inspect', 'smoke', 'trivy', 'syft', 'grype', 'dockle',
    'trivy-metadata', 'grype-metadata', 'trivy-sarif', 'export-image',
)


def load_json(path):
    return json.loads(path.read_text(encoding='utf-8'))


def vulnerability_records(trivy, grype):
    records = []
    for result in trivy.get('Results', []):
        for item in result.get('Vulnerabilities', []):
            records.append({
                'tool': 'trivy', 'rule': item['VulnerabilityID'],
                'subject': item['PkgName'], 'version': item.get('InstalledVersion', ''),
                'severity': item['Severity'].upper(), 'fixable': bool(item.get('FixedVersion')),
            })
    for match in grype['matches']:
        vulnerability = match['vulnerability']
        fix = vulnerability.get('fix', {})
        records.append({
            'tool': 'grype', 'rule': vulnerability['id'],
            'subject': match['artifact']['name'], 'version': match['artifact'].get('version', ''),
            'severity': vulnerability['severity'].upper(),
            'fixable': fix.get('state') == 'fixed' and bool(fix.get('versions')),
        })
    # A vulnerability can occur in multiple image paths or layers.
    unique = {(r['tool'], r['rule'], r['subject'], r['version']): r for r in records}
    return list(unique.values())


def checkov_findings(report, framework, required_checks):
    reports = report if isinstance(report, list) else [report]
    matching = [r for r in reports if r.get('check_type') == framework]
    if not matching:
        raise ValueError(f'Checkov {framework} report missing')
    observed = set()
    findings = []
    for item in matching:
        if item.get('summary', {}).get('parsing_errors', 0):
            raise ValueError(f'Checkov {framework} encountered parsing errors')
        results = item['results']
        for status in ('passed_checks', 'failed_checks', 'skipped_checks'):
            for check in results.get(status, []):
                rule = check['check_id']
                if status != 'skipped_checks':
                    observed.add(rule)
                if rule in required_checks and status != 'passed_checks':
                    findings.append({
                        'tool': 'checkov', 'rule': rule,
                        'subject': check.get('resource', check.get('file_path', framework)),
                        'message': f'{framework}: {check.get("check_name", rule)} ({status})',
                    })
    missing = set(required_checks) - observed
    if missing:
        raise ValueError(f'Checkov {framework} required checks absent or skipped: {sorted(missing)}')
    return findings


def evaluate(directory, policy_path=ROOT / 'policy' / 'gates.json'):
    errors = []
    findings = []
    vulnerabilities = []
    policy = load_json(policy_path)
    run = load_json(directory / 'run.json')
    for name in REQUIRED_STAGES:
        stage = run['stages'].get(name)
        if not stage or stage.get('status') != 'ok':
            errors.append(f'{name}: {(stage or {}).get("error", "missing or incomplete stage")}')

    def read(name, validator):
        try:
            document = load_json(directory / name)
            validator(document)
            return document
        except (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError) as error:
            errors.append(f'{name}: invalid or missing evidence ({error})')
            return None

    def hadolint_rules(document):
        if not isinstance(document, list):
            raise ValueError('expected a JSON list')
        for item in document:
            if item['level'] == 'error':
                findings.append({'tool': 'hadolint', 'rule': item['code'],
                                 'subject': f'{item["file"]}:{item["line"]}', 'message': item['message']})

    read('hadolint.json', hadolint_rules)
    for framework in ('kubernetes', 'terraform'):
        def validate_checkov(document, framework=framework):
            findings.extend(checkov_findings(document, framework, policy[f'required_{framework}_checks']))
        read(f'checkov-{framework}.json', validate_checkov)

    def infrastructure_rules(document):
        if document['kubernetes_documents'] < 3 or document['terraform_deployments'] < 1:
            raise ValueError('infrastructure coverage incomplete')
        for item in document['findings']:
            findings.append({'tool': 'infrastructure', 'rule': item['id'],
                             'subject': item['resource'], 'message': item['message']})

    read('infra-policy.json', infrastructure_rules)

    def inspect_rules(document):
        image = document[0]
        user = image['Config'].get('User', '')
        uid = user.split(':', 1)[0]
        if not uid.isdigit() or int(uid) == 0:
            findings.append({'tool': 'image', 'rule': 'PROJECT_NON_ROOT', 'subject': 'Config.User',
                             'message': 'Image must declare a positive numeric runtime UID'})
        if image['Size'] <= 0 or not image['Id'].startswith('sha256:'):
            raise ValueError('invalid image metadata')

    read('image-inspect.json', inspect_rules)

    def trivy_rules(document):
        if document['SchemaVersion'] != 2 or document.get('ArtifactType') != 'container_image':
            raise ValueError('unsupported Trivy image report')
        for result in document.get('Results', []):
            for secret in result.get('Secrets', []):
                findings.append({'tool': 'trivy', 'rule': secret['RuleID'], 'subject': result['Target'],
                                 'message': 'Secret detected in image'})

    trivy = read('trivy.json', trivy_rules)

    def grype_rules(document):
        database = document['descriptor']['db']
        status = database.get('status', database)
        if not isinstance(document['matches'], list) or not status['built'] or status.get('valid') is False:
            raise ValueError('Grype matches or database metadata missing')

    grype = read('grype.json', grype_rules)

    def sbom_rules(document):
        if not isinstance(document['artifacts'], list) or not document['artifacts']:
            raise ValueError('empty SBOM inventory')

    read('sbom.syft.json', sbom_rules)

    def cyclonedx_rules(document):
        if document['bomFormat'] != 'CycloneDX' or not document['components']:
            raise ValueError('invalid CycloneDX SBOM')

    read('sbom.cdx.json', cyclonedx_rules)

    def dockle_rules(document):
        details = document['details'] or []
        fatal_count = document['summary']['fatal']
        if not isinstance(details, list) or not isinstance(fatal_count, int) or fatal_count < 0:
            raise ValueError('invalid Dockle report')
        if fatal_count != sum(item['level'] == 'FATAL' for item in details):
            raise ValueError('Dockle fatal summary does not match detail records')
        for item in details:
            if item['level'] == 'FATAL':
                findings.append({'tool': 'dockle', 'rule': item['code'], 'subject': 'image',
                                 'message': item['title']})

    read('dockle.json', dockle_rules)

    def sarif_rules(document):
        if document['version'] != '2.1.0' or not document['runs']:
            raise ValueError('invalid SARIF report')

    read('trivy.sarif', sarif_rules)
    def metadata_rules(document):
        if not isinstance(document, dict) or not document:
            raise ValueError('empty database metadata')

    read('trivy-version.json', metadata_rules)
    read('grype-db.json', metadata_rules)
    if trivy is not None and grype is not None:
        try:
            vulnerabilities = vulnerability_records(trivy, grype)
            for item in vulnerabilities:
                if item['fixable'] and item['severity'] in policy['fixable_vulnerability_severities']:
                    findings.append({**item, 'message': 'Fixable HIGH/CRITICAL vulnerability'})
        except (ValueError, KeyError, TypeError, AttributeError) as error:
            errors.append(f'Vulnerability report parsing failed: {error}')

    exceptions = policy['exceptions']
    for exception in exceptions:
        try:
            if not exception['justification'].strip() or date.fromisoformat(exception['review_date']) < date.today():
                raise ValueError('missing justification or expired review date')
            for field in ('tool', 'rule', 'subject'):
                if not exception[field]:
                    raise ValueError(f'missing {field}')
        except (ValueError, KeyError, TypeError) as error:
            errors.append(f'Invalid policy exception: {error}')
    accepted = []
    blocking = []
    for finding in findings:
        matching = [e for e in exceptions if all(e.get(k) == finding[k] for k in ('tool', 'rule', 'subject'))]
        (accepted if matching else blocking).append(finding)

    counts = {}
    for tool in ('trivy', 'grype'):
        counts[tool] = dict(Counter(r['severity'] for r in vulnerabilities if r['tool'] == tool))
    result = {
        'variant': run['variant'], 'passed': not errors and not blocking,
        'errors': errors, 'blocking_findings': blocking, 'accepted_findings': accepted,
        'vulnerabilities': vulnerabilities, 'severity_counts': counts,
    }
    (directory / 'gate.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('reports', type=Path)
    args = parser.parse_args()
    result = evaluate(args.reports)
    print(json.dumps({k: v for k, v in result.items() if k != 'vulnerabilities'}, indent=2))
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
