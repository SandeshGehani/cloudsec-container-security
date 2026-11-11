"""Create an HTML evidence report and a compact GitHub job summary."""

import argparse
from collections import Counter
import html
import json
from pathlib import Path


def write_report(directory, gate):
    run = json.loads((directory / 'run.json').read_text())
    status = 'PASS' if gate['passed'] else 'FAIL'
    rows = ''.join(
        f'<tr><td>{html.escape(name)}</td><td>{stage["status"]}</td><td>{stage["duration_seconds"]:.3f}</td></tr>'
        for name, stage in run['stages'].items()
    )
    findings = ''.join(
        '<li>' + html.escape(f'{item["tool"]} / {item["rule"]} / {item["subject"]} — {item["message"]}') + '</li>'
        for item in gate['blocking_findings']
    )
    errors = ''.join(f'<li>{html.escape(error)}</li>' for error in gate['errors'])
    counts = html.escape(json.dumps(gate['severity_counts'], indent=2))
    content = f'''<!doctype html>
<html lang="en"><meta charset="utf-8"><title>Container security scan report</title>
<style>body{{font:16px system-ui;max-width:1100px;margin:40px auto;padding:20px;color:#182a35}}
table{{border-collapse:collapse;width:100%}}td,th{{text-align:left;padding:10px;border-bottom:1px solid #ccc}}
li{{margin:10px 0;overflow-wrap:anywhere}}pre{{white-space:pre-wrap}}</style>
<h1>{html.escape(run['variant'])} security gate {status}</h1>
<p>Started {html.escape(run['started_at'])}. Commit {html.escape(run['commit'])}.
Collection duration {run['duration_seconds']:.3f} seconds. Cache enabled {run['cache_enabled']}.</p>
<h2>Collection errors</h2><ul>{errors}</ul>
<h2>Blocking findings</h2><ul>{findings}</ul>
<h2>Unique package vulnerability findings by severity</h2><pre>{counts}</pre>
<h2>Pipeline stages</h2><table><tr><th>Stage</th><th>Status</th><th>Seconds</th></tr>{rows}</table>
<h2>Accepted findings</h2><pre>{html.escape(json.dumps(gate['accepted_findings'], indent=2))}</pre>
<h2>Tool versions and checksums</h2><pre>{html.escape(json.dumps(run['tool_versions'], indent=2))}</pre>
</html>'''
    (directory / 'report.html').write_text(content, encoding='utf-8')
    markdown = (
        f'## {run["variant"]} security gate {status}\n\n'
        f'- Blocking findings — {len(gate["blocking_findings"])}\n'
        f'- Collection errors — {len(gate["errors"])}\n'
        f'- Collection duration — {run["duration_seconds"]:.3f} seconds\n'
        f'- Cache enabled — {run["cache_enabled"]}\n\n'
        'Download the evidence artifact for raw JSON, SARIF, SBOMs, and the HTML report.\n'
    )
    (directory / 'summary.md').write_text(markdown, encoding='utf-8')


def compare(baseline, hardened, output):
    gates = [json.loads((directory / 'gate.json').read_text()) for directory in (baseline, hardened)]
    runs = [json.loads((directory / 'run.json').read_text()) for directory in (baseline, hardened)]
    result = {'variants': {}}
    for directory, gate, run in zip((baseline, hardened), gates, runs):
        identifiers = {
            tool: {r['rule'] for r in gate['vulnerabilities'] if r['tool'] == tool}
            for tool in ('trivy', 'grype')
        }
        image_path = directory / 'image-inspect.json'
        image = json.loads(image_path.read_text())[0] if image_path.exists() else {}
        result['variants'][gate['variant']] = {
            'passed': gate['passed'], 'errors': gate['errors'],
            'severity_counts': gate['severity_counts'],
            'blocking_findings_by_tool': dict(Counter(r['tool'] for r in gate['blocking_findings'])),
            'image_size_bytes': image.get('Size'), 'image_id': image.get('Id'),
            'duration_seconds': run['duration_seconds'], 'cache_enabled': run['cache_enabled'],
            'started_at': run['started_at'], 'stage_timings': run['stages'],
            'overlap_exact_vulnerability_ids': sorted(identifiers['trivy'] & identifiers['grype']),
            'trivy_only_exact_ids': sorted(identifiers['trivy'] - identifiers['grype']),
            'grype_only_exact_ids': sorted(identifiers['grype'] - identifiers['trivy']),
        }
    result['limitations'] = [
        'Overlap compares exact reported vulnerability IDs. CVE and GHSA aliases can represent the same issue.',
        'False-positive rates require manual review of a documented sample.',
        'Compare cached and uncached runs separately and record database timestamps from raw reports.',
    ]
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2), encoding='utf-8')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--hardened', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    compare(args.baseline, args.hardened, args.output)


if __name__ == '__main__':
    main()
