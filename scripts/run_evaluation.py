"""Measure three cold and three warm runs on one runner for a single variant."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def observed_cache(variant):
    cache = ROOT / '.cache'
    return {
        'buildx_index': (cache / 'buildx' / variant / 'index.json').is_file(),
        'trivy_database': (cache / 'trivy' / 'db' / 'trivy.db').is_file(),
        'grype_database': any((cache / 'grype').glob('**/vulnerability.db')),
    }


def measure(variant, condition, trial, output):
    directory = output / f'{condition}-{trial}'
    cache_before = observed_cache(variant)
    command = [sys.executable, str(ROOT / 'scripts' / 'run_pipeline.py'),
               '--variant', variant, '--reports', str(directory)]
    if condition == 'cold':
        command.append('--no-cache')
    if variant == 'baseline':
        command.append('--baseline-evaluation')
    started = time.monotonic()
    with (output / f'{condition}-{trial}.log').open('wb') as log:
        process = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, timeout=1800)
    elapsed = round(time.monotonic() - started, 3)
    run = json.loads((directory / 'run.json').read_text(encoding='utf-8'))
    gate = json.loads((directory / 'gate.json').read_text(encoding='utf-8'))
    row = {
        'variant': variant, 'condition': condition, 'trial': trial,
        'started_at': run['started_at'], 'commit': run['commit'],
        'collector_seconds': run['duration_seconds'], 'process_seconds': elapsed,
        'stages': run['stages'], 'passed': gate['passed'], 'collection_errors': gate['errors'],
        'blocking_findings': len(gate['blocking_findings']),
        'cache_observed_before': cache_before, 'exit_code': process.returncode,
    }
    (directory / 'measurement.json').write_text(json.dumps(row, indent=2), encoding='utf-8')
    # These intermediates belong to this fresh evaluation directory and have completed their checks.
    (directory / 'image.tar').unlink(missing_ok=True)
    cold_cache = (directory / 'cold-cache').resolve()
    if cold_cache.is_dir():
        if not cold_cache.is_relative_to(directory.resolve()):
            raise RuntimeError('Cold-cache cleanup escaped its evaluation directory')
        shutil.rmtree(cold_cache)
    if process.returncode:
        raise RuntimeError(f'{condition} trial {trial} failed. Review {directory} and its process log.')
    if condition == 'warm' and not all(cache_before.values()):
        raise RuntimeError(f'Warm trial {trial} began without all required caches')
    print(json.dumps({k: row[k] for k in ('variant', 'condition', 'trial', 'collector_seconds', 'passed')}), flush=True)
    return row


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--variant', choices=('baseline', 'hardened'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    rows = []
    result = {
        'variant': args.variant, 'started_at': datetime.now(timezone.utc).isoformat(),
        'design': 'Three cold trials, one excluded warm-up, then three warm trials on the same runner.',
        'cold_definition': 'Docker build cache disabled with fresh vulnerability database directories.',
        'warm_definition': 'Buildx cache and both vulnerability databases present before each measured warm trial.',
        'limitations': ['Base-image downloads can remain cached after the first cold trial.',
                        'Condition order and network variation can affect timing.',
                        'Each variant uses its own runner. The sample size is three per condition.'],
        'measurements': rows,
    }
    try:
        for trial in range(1, 4):
            rows.append(measure(args.variant, 'cold', trial, output))
        measure(args.variant, 'warmup', 0, output)
        for trial in range(1, 4):
            rows.append(measure(args.variant, 'warm', trial, output))
        result['statistics'] = {}
        for condition in ('cold', 'warm'):
            values = [row['collector_seconds'] for row in rows if row['condition'] == condition]
            result['statistics'][condition] = {
                'n': len(values), 'median_seconds': statistics.median(values),
                'mean_seconds': statistics.mean(values), 'sample_stdev_seconds': statistics.stdev(values),
                'minimum_seconds': min(values), 'maximum_seconds': max(values),
            }
        result['completed'] = True
    finally:
        result['finished_at'] = datetime.now(timezone.utc).isoformat()
        (output / 'evaluation.json').write_text(json.dumps(result, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
