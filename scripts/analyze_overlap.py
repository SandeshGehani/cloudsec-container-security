"""Compare scanner findings using explicit advisory aliases and package identity."""

import argparse
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import unquote


def load(directory, name):
    return json.loads((directory / name).read_text(encoding='utf-8'))


def package_key(purl, name, version):
    ecosystem = 'unknown'
    if purl.startswith('pkg:'):
        identity = purl[4:].split('@', 1)[0].split('?', 1)[0]
        ecosystem, _, qualified_name = identity.partition('/')
        name = unquote(qualified_name.rsplit('/', 1)[-1])
    if ecosystem == 'pypi':
        name = re.sub(r'[-_.]+', '-', name).lower()
    return ecosystem, name, version


def compare(directory):
    trivy = load(directory, 'trivy.json')
    grype = load(directory, 'grype.json')
    parents = {}

    def root(identifier):
        parents.setdefault(identifier, identifier)
        if parents[identifier] != identifier:
            parents[identifier] = root(parents[identifier])
        return parents[identifier]

    def join(first, second):
        parents[root(second)] = root(first)

    # Only explicit related-advisory records establish equivalence.
    for match in grype['matches']:
        identifier = match['vulnerability']['id']
        for related in match.get('relatedVulnerabilities', []):
            join(identifier, related['id'])

    groups = {}
    for identifier in list(parents):
        groups.setdefault(root(identifier), []).append(identifier)
    canonical = {}
    for identifiers in groups.values():
        preferred = min(identifiers, key=lambda item: (not item.startswith('CVE-'), item))
        canonical.update(dict.fromkeys(identifiers, preferred))

    records = {'trivy': set(), 'grype': set()}
    for result in trivy.get('Results', []):
        for item in result.get('Vulnerabilities', []):
            key = package_key(item.get('PkgIdentifier', {}).get('PURL', ''),
                              item['PkgName'], item['InstalledVersion'])
            records['trivy'].add((item['VulnerabilityID'], *key))
    for match in grype['matches']:
        artifact = match['artifact']
        key = package_key(artifact.get('purl', ''), artifact['name'], artifact['version'])
        records['grype'].add((match['vulnerability']['id'], *key))

    def counts(first, second):
        union = first | second
        return {
            'trivy': len(first), 'grype': len(second), 'shared': len(first & second),
            'trivy_only': len(first - second), 'grype_only': len(second - first),
            'jaccard': len(first & second) / len(union) if union else None,
        }

    exact_ids = [{record[0] for record in records[tool]} for tool in records]
    normalized = {
        tool: {(canonical.get(row[0], row[0]), *row[1:]) for row in rows}
        for tool, rows in records.items()
    }
    normalized_ids = [{row[0] for row in normalized[tool]} for tool in normalized]
    evidence = {}
    for name in ('run.json', 'trivy.json', 'grype.json', 'gate.json', 'sbom.syft.json'):
        evidence[name] = hashlib.sha256((directory / name).read_bytes()).hexdigest()
    return {
        'commit': load(directory, 'run.json')['commit'],
        'exact_advisory_ids': counts(*exact_ids),
        'alias_normalized_advisory_ids': counts(*normalized_ids),
        'alias_normalized_package_findings': counts(normalized['trivy'], normalized['grype']),
        'explicit_alias_groups': sorted(sorted(group) for group in groups.values() if len(group) > 1),
        'unknown_package_ecosystem': {
            tool: sum(row[1] == 'unknown' for row in rows) for tool, rows in records.items()
        },
        'evidence_sha256': evidence,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--hardened', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = {
        'method': 'Deduplicate by advisory, PURL ecosystem, package name, and installed version. '
                  'Normalize PyPI names. Join only Grype explicit related-advisory IDs. '
                  'Keep Debian binary packages separate. Compare exact versions.',
        'limitations': ['An unmatched report record does not establish a false positive or missed vulnerability.',
                        'Alias coverage is limited to the related-advisory links present in these reports.',
                        'Package cataloguing and source versus binary matching differ between scanners.'],
        'variants': {'baseline': compare(args.baseline), 'hardened': compare(args.hardened)},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
