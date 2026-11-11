"""Verify the YAML and Terraform deployments in a dedicated disposable kind cluster."""

import argparse
from datetime import datetime, timezone
import json
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import time
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
CONTEXT = 'kind-container-security'
PROBE_NAMESPACE = 'taskboard-policy-probes'


def command(arguments, output, name):
    result = subprocess.run(arguments, cwd=ROOT, capture_output=True, timeout=600)
    (output / f'{name}.log').write_bytes(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f'{name} failed with exit code {result.returncode}')
    return result.stdout.decode('utf-8').strip()


def install_calico(output):
    config = json.loads((ROOT / 'tools/network-versions.json').read_text(encoding='utf-8'))['calico']
    with urllib.request.urlopen(config['url'], timeout=60) as response:
        manifest = response.read()
    if hashlib.sha256(manifest).hexdigest() != config['sha256']:
        raise RuntimeError('Calico manifest checksum did not match the pinned release')
    path = output / 'calico.yaml'
    path.write_bytes(manifest)
    kubectl = ['kubectl', '--context', CONTEXT]
    command(kubectl + ['create', '-f', str(path)], output, 'calico-install')
    command(kubectl + ['-n', 'kube-system', 'rollout', 'status', 'daemonset/calico-node', '--timeout=300s'],
            output, 'calico-node-ready')
    command(kubectl + ['-n', 'kube-system', 'rollout', 'status', 'deployment/calico-kube-controllers', '--timeout=300s'],
            output, 'calico-controllers-ready')
    command(kubectl + ['wait', '--for=condition=Ready', 'nodes', '--all', '--timeout=300s'], output, 'nodes-ready')
    return config


def create_probe(namespace, name, node, output, server=False):
    container = {
        'name': 'probe', 'image': 'taskboard:hardened', 'imagePullPolicy': 'Never',
        'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                            'capabilities': {'drop': ['ALL']}},
        'resources': {'requests': {'cpu': '25m', 'memory': '32Mi'},
                      'limits': {'cpu': '250m', 'memory': '128Mi'}},
        'volumeMounts': [{'name': 'tmp', 'mountPath': '/tmp'}],
    }
    if not server:
        container['command'] = ['python', '-c', 'import time; time.sleep(900)']
    pod = {
        'apiVersion': 'v1', 'kind': 'Pod',
        'metadata': {'name': name, 'namespace': namespace, 'labels': {'app': 'network-probe'}},
        'spec': {
            'nodeName': node, 'restartPolicy': 'Never', 'automountServiceAccountToken': False,
            'securityContext': {'runAsNonRoot': True, 'runAsUser': 10001, 'runAsGroup': 10001,
                                'fsGroup': 10001, 'seccompProfile': {'type': 'RuntimeDefault'}},
            'containers': [container], 'volumes': [{'name': 'tmp', 'emptyDir': {'sizeLimit': '32Mi'}}],
        },
    }
    path = output / f'{namespace}-{name}.json'
    path.write_text(json.dumps(pod, indent=2), encoding='utf-8')
    kubectl = ['kubectl', '--context', CONTEXT, '-n', namespace]
    command(kubectl + ['apply', '-f', str(path)], output, f'{namespace}-{name}-create')
    command(kubectl + ['wait', '--for=condition=Ready', f'pod/{name}', '--timeout=120s'],
            output, f'{namespace}-{name}-ready')
    return json.loads(command(kubectl + ['get', f'pod/{name}', '-o', 'json'],
                              output, f'{namespace}-{name}-state'))['status']['podIP']


def traffic_probe(namespace, source, destination, allowed, output, name):
    script = (
        'import json, urllib.request, urllib.error\n'
        f'url = "http://{destination}:8080/healthz"\n'
        'try:\n'
        ' with urllib.request.urlopen(url, timeout=2) as response:\n'
        '  assert json.load(response) == {"status": "ok"}\n'
        ' print(json.dumps({"reachable": True}))\n'
        'except (OSError, urllib.error.URLError) as error:\n'
        ' reason = getattr(error, "reason", error)\n'
        ' print(json.dumps({"reachable": False, "error": type(reason).__name__}))\n'
    )
    kubectl = ['kubectl', '--context', CONTEXT, '-n', namespace]
    attempts = []
    consecutive = 0
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        observation = json.loads(command(kubectl + ['exec', source, '--', 'python', '-c', script],
                                         output, f'{name}-{len(attempts) + 1}'))
        attempts.append(observation)
        matched = observation['reachable'] if allowed else observation.get('error') == 'TimeoutError'
        consecutive = consecutive + 1 if matched else 0
        if consecutive == 2:
            return {'source_namespace': namespace, 'source': source, 'destination_ip': destination,
                    'expected': 'allowed' if allowed else 'denied', 'passed': True, 'attempts': attempts}
        time.sleep(1)
    raise RuntimeError(f'{name} did not reach the expected traffic state. Attempts {attempts}')


def verify_network_policy(namespace, probe_node, receiver_ip, output):
    kubectl = ['kubectl', '--context', CONTEXT, '-n', namespace]
    pods = json.loads(command(kubectl + ['get', 'pods', '-l', 'app=taskboard', '-o', 'json'],
                              output, f'{namespace}-target-pod'))['items']
    assert len(pods) == 1
    target = pods[0]
    assert target['spec']['nodeName'] != probe_node
    target_ip = target['status']['podIP']
    create_probe(namespace, 'allowed-client', probe_node, output)
    policy = json.loads(command(kubectl + ['get', 'networkpolicy/taskboard-isolation', '-o', 'json'],
                                output, f'{namespace}-policy-original'))
    restore = {'apiVersion': policy['apiVersion'], 'kind': policy['kind'], 'spec': policy['spec'],
               'metadata': {'name': policy['metadata']['name'], 'namespace': namespace}}
    restore_path = output / f'{namespace}-policy-restore.json'
    restore_path.write_text(json.dumps(restore, indent=2), encoding='utf-8')
    checks = []
    result = {'namespace': namespace, 'client_node': probe_node, 'application_node': target['spec']['nodeName'],
              'cross_node': True, 'checks': checks, 'passed': False}

    def check(phase, label, source_namespace, source, destination, allowed):
        row = traffic_probe(source_namespace, source, destination, allowed, output,
                            f'{namespace}-{phase}-{label}')
        row.update({'phase': phase, 'check': label})
        checks.append(row)

    try:
        try:
            check('enforced', 'same-namespace-ingress', namespace, 'pod/allowed-client', target_ip, True)
            check('enforced', 'cross-namespace-ingress', PROBE_NAMESPACE, 'pod/outside-client', target_ip, False)
            check('enforced', 'application-egress', namespace, 'deployment/taskboard', receiver_ip, False)
            command(kubectl + ['delete', 'networkpolicy/taskboard-isolation'], output, f'{namespace}-policy-control-remove')
            check('control-without-policy', 'cross-namespace-ingress', PROBE_NAMESPACE, 'pod/outside-client', target_ip, True)
            check('control-without-policy', 'application-egress', namespace, 'deployment/taskboard', receiver_ip, True)
        finally:
            command(kubectl + ['apply', '-f', str(restore_path)], output, f'{namespace}-policy-restored')
        check('restored', 'cross-namespace-ingress', PROBE_NAMESPACE, 'pod/outside-client', target_ip, False)
        check('restored', 'application-egress', namespace, 'deployment/taskboard', receiver_ip, False)
        check('restored', 'same-namespace-ingress', namespace, 'pod/allowed-client', target_ip, True)
        result['passed'] = True
        return result
    finally:
        (output / f'{namespace}-traffic.json').write_text(json.dumps(result, indent=2), encoding='utf-8')


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
              'environment': 'GitHub-hosted Ubuntu runner' if os.environ.get('GITHUB_ACTIONS') else 'Local Docker host',
              'context': CONTEXT, 'deployments': [],
              'networkpolicy_scope': 'Cross-node allowed ingress, denied cross-namespace ingress and denied application egress, with policy-removal and restoration controls.'}
    created = False
    try:
        existing = command(['kind', 'get', 'clusters'], output, 'existing-clusters').splitlines()
        if 'container-security' in existing:
            raise RuntimeError('The container-security cluster already exists. Use a fresh Docker environment for this verifier.')
        created = True
        command(['kind', 'create', 'cluster', '--name', 'container-security', '--config', 'infra/kind-calico.yaml',
                 '--image', 'kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5'],
                output, 'cluster-create')
        result['cni'] = install_calico(output)
        command(['docker', 'buildx', 'build', '--load', '--file', 'Dockerfile', '--tag', 'taskboard:hardened', '.'], output, 'image-build')
        command(['docker', 'image', 'inspect', 'taskboard:hardened'], output, 'image-inspect')
        command(['kind', 'load', 'docker-image', 'taskboard:hardened', '--name', 'container-security'], output, 'image-load')
        nodes = json.loads(command(['kubectl', '--context', CONTEXT, 'get', 'nodes', '-o', 'json'], output, 'nodes'))['items']
        probe_node = next(node['metadata']['name'] for node in nodes
                          if 'node-role.kubernetes.io/control-plane' in node['metadata']['labels'])
        command(['kubectl', '--context', CONTEXT, 'create', 'namespace', PROBE_NAMESPACE], output, 'probe-namespace')
        create_probe(PROBE_NAMESPACE, 'outside-client', probe_node, output)
        receiver_ip = create_probe(PROBE_NAMESPACE, 'receiver', probe_node, output, server=True)
        traffic_probe(PROBE_NAMESPACE, 'pod/outside-client', receiver_ip, True, output, 'receiver-positive-control')
        command(['kubectl', '--context', CONTEXT, 'apply', '-f', 'infra/kubernetes/hardened/app.yaml'], output, 'yaml-apply')
        result['deployments'].append(verify_namespace('taskboard-hardened', 18080, output))
        result['deployments'][-1]['network_policy'] = verify_network_policy('taskboard-hardened', probe_node, receiver_ip, output)
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
        result['deployments'][-1]['network_policy'] = verify_network_policy('taskboard-terraform', probe_node, receiver_ip, output)
        command(['kubectl', '--context', CONTEXT, 'get', 'pods', '-A', '-o', 'wide'], output, 'cluster-pods')
        result['passed'] = True
    except Exception as error:
        result['passed'] = False
        result['error'] = str(error)
        raise
    finally:
        try:
            if created:
                command(['kind', 'delete', 'cluster', '--name', 'container-security'], output, 'cluster-cleanup')
        except Exception as error:
            result['passed'] = False
            result['cleanup_error'] = str(error)
            raise
        finally:
            result['finished_at'] = datetime.now(timezone.utc).isoformat()
            (output / 'verification.json').write_text(json.dumps(result, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
