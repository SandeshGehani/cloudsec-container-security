"""Verify the YAML and Terraform deployments in a dedicated disposable kind cluster."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
CONTEXT = 'kind-container-security'


def command(arguments, output, name):
    result = subprocess.run(arguments, cwd=ROOT, capture_output=True, timeout=600)
    (output / f'{name}.log').write_bytes(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f'{name} failed with exit code {result.returncode}')
    return result.stdout.decode('utf-8').strip()


def verify_namespace(namespace, port, output):
    kubectl = ['kubectl', '--context', CONTEXT, '--namespace', namespace]
    command(kubectl + ['rollout', 'status', 'deployment/taskboard', '--timeout=180s'], output, f'{namespace}-rollout')
    deployment = json.loads(command(kubectl + ['get', 'deployment/taskboard', '-o', 'json'], output, f'{namespace}-deployment'))
    spec = deployment['spec']['template']['spec']
    container = spec['containers'][0]
    assert deployment['status']['readyReplicas'] == 1
    assert container['securityContext']['readOnlyRootFilesystem'] is True
    assert container['securityContext']['allowPrivilegeEscalation'] is False
    assert container['securityContext']['privileged'] is False
    assert container['securityContext']['capabilities']['drop'] == ['ALL']
    assert spec['automountServiceAccountToken'] is False
    uid = command(kubectl + ['exec', 'deployment/taskboard', '--', 'python', '-c', 'import os; print(os.getuid())'], output, f'{namespace}-uid')
    assert uid == '10001'
    probe = (
        'import errno; from pathlib import Path\n'
        'try:\n Path("/app/write-probe").write_text("probe")\n'
        'except OSError as error:\n assert error.errno in (errno.EROFS, errno.EACCES); print("root filesystem write rejected")\n'
        'else:\n raise RuntimeError("root filesystem was writable")\n'
    )
    command(kubectl + ['exec', 'deployment/taskboard', '--', 'python', '-c', probe], output, f'{namespace}-readonly')
    command(kubectl + ['get', 'networkpolicy/taskboard-isolation', '-o', 'json'], output, f'{namespace}-networkpolicy')
    with (output / f'{namespace}-port-forward.log').open('wb') as log:
        forwarding = subprocess.Popen(kubectl + ['port-forward', '--address', '127.0.0.1', 'service/taskboard', f'{port}:8080'],
                                      cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        try:
            base = f'http://127.0.0.1:{port}'
            deadline = time.monotonic() + 40
            while True:
                try:
                    with urllib.request.urlopen(base + '/healthz', timeout=2) as response:
                        assert json.load(response) == {'status': 'ok'}
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError('Port-forward health check timed out')
                    time.sleep(1)
            request = urllib.request.Request(base + '/tasks', data=urllib.parse.urlencode({'title': 'Verified Kubernetes deployment'}).encode())
            with urllib.request.urlopen(request, timeout=5) as response:
                page = response.read()
                assert b'Verified Kubernetes deployment' in page
                (output / f'{namespace}-response.html').write_bytes(page)
            chrome = shutil.which('google-chrome') or shutil.which('chromium')
            if chrome:
                command([chrome, '--headless', '--no-sandbox', '--disable-gpu', '--hide-scrollbars',
                         '--window-size=1440,1000', '--virtual-time-budget=2000',
                         f'--screenshot={output / (namespace + ".png")}', base], output, f'{namespace}-screenshot')
        finally:
            forwarding.terminate()
            forwarding.wait(timeout=10)
    return {'namespace': namespace, 'ready_replicas': 1, 'runtime_uid': int(uid),
            'health_check': 'passed', 'task_creation': 'passed', 'root_filesystem_write': 'rejected',
            'privileged': False, 'privilege_escalation': False, 'networkpolicy_resource': 'present'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    result = {'started_at': datetime.now(timezone.utc).isoformat(),
              'commit': os.environ.get('GITHUB_SHA', 'local'),
              'environment': 'GitHub-hosted Ubuntu runner with a disposable kind cluster',
              'context': CONTEXT, 'deployments': [],
              'networkpolicy_scope': 'Resource creation verified. Runtime traffic enforcement requires a compatible CNI.'}
    created = False
    try:
        command(['kind', 'create', 'cluster', '--name', 'container-security', '--config', 'infra/kind.yaml',
                 '--image', 'kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5',
                 '--wait', '180s'], output, 'cluster-create')
        created = True
        command(['docker', 'buildx', 'build', '--load', '--file', 'Dockerfile', '--tag', 'taskboard:hardened', '.'], output, 'image-build')
        command(['docker', 'image', 'inspect', 'taskboard:hardened'], output, 'image-inspect')
        command(['kind', 'load', 'docker-image', 'taskboard:hardened', '--name', 'container-security'], output, 'image-load')
        command(['kubectl', '--context', CONTEXT, 'apply', '-f', 'infra/kubernetes/hardened/app.yaml'], output, 'yaml-apply')
        result['deployments'].append(verify_namespace('taskboard-hardened', 18080, output))
        terraform = ['terraform', '-chdir=infra/terraform']
        command(terraform + ['init', '-input=false'], output, 'terraform-init')
        command(terraform + ['validate', '-json'], output, 'terraform-validate')
        plan = output / 'deployment.tfplan'
        command(terraform + ['plan', '-input=false', '-out', str(plan)], output, 'terraform-plan')
        planned = json.loads(command(terraform + ['show', '-json', str(plan)], output, 'terraform-plan-json'))
        expected = {'kubernetes_namespace_v1.app', 'kubernetes_deployment_v1.app',
                    'kubernetes_service_v1.app', 'kubernetes_network_policy_v1.app'}
        changes = planned['resource_changes']
        assert {item['address'] for item in changes} == expected
        assert all(item['change']['actions'] == ['create'] for item in changes)
        command(terraform + ['apply', '-input=false', str(plan)], output, 'terraform-apply')
        result['deployments'].append(verify_namespace('taskboard-terraform', 18081, output))
        command(['kubectl', '--context', CONTEXT, 'get', 'pods', '-A', '-o', 'wide'], output, 'cluster-pods')
        result['passed'] = True
    except Exception as error:
        result['passed'] = False
        result['error'] = str(error)
        raise
    finally:
        if created:
            command(['kind', 'delete', 'cluster', '--name', 'container-security'], output, 'cluster-cleanup')
        result['finished_at'] = datetime.now(timezone.utc).isoformat()
        (output / 'verification.json').write_text(json.dumps(result, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
