"""Collect every available scan result, then enforce a single final security gate."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.parse
import urllib.request
import uuid

from evaluate import evaluate
from infra_policy import evaluate_infrastructure
from report import write_report

ROOT = Path(__file__).resolve().parents[1]


class Pipeline:
    def __init__(self, variant, destination, cache):
        self.destination = destination
        destination.mkdir(parents=True, exist_ok=False)
        self.image = f'taskboard:{variant}'
        self.started = time.monotonic()
        self.run = {
            'variant': variant, 'cache_enabled': cache,
            'started_at': datetime.now(timezone.utc).isoformat(),
            'commit': os.environ.get('GITHUB_SHA', 'local'),
            'tool_versions': json.loads((ROOT / 'tools' / 'versions.json').read_text()),
            'policy_sha256': hashlib.sha256((ROOT / 'policy' / 'gates.json').read_bytes()).hexdigest(),
            'stages': {},
        }
        self.environment = dict(os.environ)
        self.environment['PATH'] = str(ROOT / '.tools' / 'bin') + os.pathsep + os.environ.get('PATH', '')
        self.environment['GIT_CONFIG_COUNT'] = '1'
        self.environment['GIT_CONFIG_KEY_0'] = 'safe.directory'
        self.environment['GIT_CONFIG_VALUE_0'] = str(ROOT)
        # Checkov's GitPython dependency can initialise even when repository checks are disabled.
        self.environment['GIT_PYTHON_REFRESH'] = 'quiet'
        cache_root = ROOT / '.cache' if cache else destination / 'cold-cache'
        self.environment['TRIVY_CACHE_DIR'] = str(cache_root / 'trivy')
        self.environment['GRYPE_DB_CACHE_DIR'] = str(cache_root / 'grype')
        self.save()

    def save(self):
        self.run['duration_seconds'] = round(time.monotonic() - self.started, 3)
        temporary = self.destination / 'run.json.tmp'
        temporary.write_text(json.dumps(self.run, indent=2), encoding='utf-8')
        temporary.replace(self.destination / 'run.json')

    def command(self, arguments, output=None, allowed_codes=(0,), timeout=900):
        result = subprocess.run(
            [str(value) for value in arguments], cwd=ROOT, env=self.environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
        )
        if output:
            (self.destination / output).write_bytes(result.stdout)
        with (self.destination / 'commands.log').open('ab') as log:
            log.write(('\n$ ' + ' '.join(str(value) for value in arguments) + '\n').encode())
            log.write(result.stderr)
            if not output:
                log.write(result.stdout)
        if result.returncode not in allowed_codes:
            raise RuntimeError(f'{arguments[0]} exited {result.returncode}. See commands.log.')
        return result.stdout.decode('utf-8', errors='replace').strip()

    def stage(self, name, operation, dependency=None):
        started = time.monotonic()
        if dependency and self.run['stages'][dependency]['status'] != 'ok':
            self.run['stages'][name] = {'status': 'unavailable', 'error': f'{dependency} failed', 'duration_seconds': 0}
            self.save()
            return
        try:
            operation()
            status = {'status': 'ok'}
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyError, TypeError) as error:
            status = {'status': 'error', 'error': str(error)}
        status['duration_seconds'] = round(time.monotonic() - started, 3)
        self.run['stages'][name] = status
        self.save()
        print(f'{name}: {status["status"]}', flush=True)

    def scan(self, variant, cache):
        dockerfile = 'Dockerfile.baseline' if variant == 'baseline' else 'Dockerfile'
        self.stage('hadolint', lambda: self.command(
            ['hadolint', '--format', 'json', '--no-fail', dockerfile], output='hadolint.json'))
        for framework, directory in (
            ('kubernetes', f'infra/kubernetes/{variant}'), ('terraform', 'infra/terraform'),
        ):
            self.stage(f'checkov-{framework}', lambda framework=framework, directory=directory: self.command(
                ['checkov', '--directory', directory, '--framework', framework,
                 '--output', 'json', '--soft-fail', '--skip-download'],
                output=f'checkov-{framework}.json'))

        def infrastructure():
            result = evaluate_infrastructure(ROOT, variant)
            (self.destination / 'infra-policy.json').write_text(json.dumps(result, indent=2), encoding='utf-8')

        self.stage('infra-policy', infrastructure)
        build = ['docker', 'buildx', 'build', '--load', '--provenance=false',
                 '--file', dockerfile, '--tag', self.image]
        if variant == 'baseline':
            build.extend(['--tag', 'taskboard:latest'])
        if cache:
            image_cache = ROOT / '.cache' / 'buildx' / variant
            if (image_cache / 'index.json').exists():
                build.extend(['--cache-from', f'type=local,src={image_cache}'])
            build.extend(['--cache-to', f'type=local,dest={image_cache},mode=max'])
        if not cache:
            build.append('--no-cache')
        if os.environ.get('GITHUB_REPOSITORY'):
            build.extend(['--label', f'org.opencontainers.image.source=https://github.com/{os.environ["GITHUB_REPOSITORY"]}'])
        build.append('.')
        self.stage('build', lambda: self.command(build, timeout=1800))
        self.stage('inspect', lambda: self.command(
            ['docker', 'image', 'inspect', self.image], output='image-inspect.json'), dependency='build')
        self.stage('smoke', self.smoke_test, dependency='build')
        self.stage('trivy', lambda: self.command(
            ['trivy', 'image', '--image-src', 'docker', '--scanners', 'vuln,secret,misconfig',
             '--secret-config', 'policy/trivy-secret.yaml', '--format', 'json', '--exit-code', '0',
             '--output', str(self.destination / 'trivy.json'), self.image]), dependency='build')
        self.stage('syft', lambda: self.command(
            ['syft', f'docker:{self.image}', '-o', f'syft-json={self.destination / "sbom.syft.json"}',
             '-o', f'cyclonedx-json={self.destination / "sbom.cdx.json"}']), dependency='build')
        self.stage('grype', lambda: self.command(
            ['grype', f'sbom:{self.destination / "sbom.syft.json"}', '-o', 'json'],
            output='grype.json'), dependency='syft')
        self.stage('dockle', lambda: self.command(
            ['dockle', '--format', 'json', '--exit-code', '0', self.image], output='dockle.json'), dependency='build')
        self.stage('trivy-metadata', lambda: self.command(
            ['trivy', 'version', '--format', 'json'], output='trivy-version.json'), dependency='trivy')
        self.stage('grype-metadata', lambda: self.command(
            ['grype', 'db', 'status', '--output', 'json'], output='grype-db.json'), dependency='grype')
        self.stage('trivy-sarif', lambda: self.command(
            ['trivy', 'convert', '--format', 'sarif', '--output', str(self.destination / 'trivy.sarif'),
             str(self.destination / 'trivy.json')]), dependency='trivy')
        self.stage('export-image', lambda: self.command(
            ['docker', 'save', '--output', str(self.destination / 'image.tar'), self.image], timeout=300), dependency='build')
        self.run['finished_at'] = datetime.now(timezone.utc).isoformat()
        self.save()

    def smoke_test(self):
        name = f'taskboard-smoke-{uuid.uuid4().hex[:12]}'
        try:
            self.command(['docker', 'run', '--detach', '--name', name, '--read-only',
                          '--tmpfs', '/tmp:rw,noexec,nosuid,size=67108864,mode=1777',
                          '--publish', '127.0.0.1::8080', self.image], timeout=60)
            port = self.command(['docker', 'port', name, '8080/tcp']).splitlines()[0].rsplit(':', 1)[1]
            base = f'http://127.0.0.1:{int(port)}'
            deadline = time.monotonic() + 40
            while True:
                try:
                    with urllib.request.urlopen(base + '/healthz', timeout=2) as response:
                        if json.load(response) != {'status': 'ok'}:
                            raise ValueError('Unexpected health response')
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError('Container did not become healthy in 40 seconds')
                    time.sleep(1)
            request = urllib.request.Request(base + '/tasks', data=urllib.parse.urlencode({'title': 'Container smoke test'}).encode())
            with urllib.request.urlopen(request, timeout=5) as response:
                if 'Container smoke test' not in response.read().decode():
                    raise RuntimeError('Task was not persisted')
        finally:
            self.command(['docker', 'rm', '--force', name], allowed_codes=(0, 1), timeout=30)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--variant', choices=('baseline', 'hardened'), required=True)
    parser.add_argument('--reports', type=Path, required=True)
    parser.add_argument('--no-cache', action='store_true')
    parser.add_argument('--baseline-evaluation', action='store_true',
                        help='Allow baseline policy findings while still failing on collection errors')
    args = parser.parse_args()
    if args.baseline_evaluation and args.variant != 'baseline':
        parser.error('--baseline-evaluation applies only to the baseline')
    directory = args.reports.resolve()
    pipeline = Pipeline(args.variant, directory, not args.no_cache)
    pipeline.scan(args.variant, not args.no_cache)
    result = evaluate(directory)
    write_report(directory, result)
    print(f'Security gate: {"PASS" if result["passed"] else "FAIL"}')
    if result['errors']:
        print('\n'.join(result['errors']))
    if args.baseline_evaluation:
        if result['passed']:
            print('Baseline unexpectedly passed. Review the demonstration fixtures.')
        raise SystemExit(1 if result['errors'] or result['passed'] else 0)
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
