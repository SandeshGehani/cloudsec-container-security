"""Supplement Checkov with explicit root-user and service exposure policies."""

import hcl2
import yaml


def evaluate_infrastructure(root, variant):
    findings = []
    documents = list(yaml.safe_load_all(
        (root / 'infra' / 'kubernetes' / variant / 'app.yaml').read_text()
    ))
    deployment_count = 0
    for document in documents:
        if document.get('kind') == 'Service':
            service_type = document.get('spec', {}).get('type', 'ClusterIP')
            if service_type != 'ClusterIP':
                findings.append({'id': 'PROJECT_PUBLIC_SERVICE', 'resource': document['metadata']['name'],
                                 'message': f'Service type {service_type} permits external exposure'})
        if document.get('kind') == 'Deployment':
            deployment_count += 1
            spec = document['spec']['template']['spec']
            pod_context = spec.get('securityContext', {})
            for container in spec.get('containers', []):
                context = {**pod_context, **container.get('securityContext', {})}
                if context.get('runAsUser', 0) <= 0 or context.get('runAsNonRoot') is not True:
                    findings.append({'id': 'PROJECT_NON_ROOT', 'resource': container['name'],
                                     'message': 'Require a positive runAsUser and runAsNonRoot=true'})
    if deployment_count == 0:
        raise ValueError('Kubernetes deployment missing')

    with (root / 'infra' / 'terraform' / 'main.tf').open() as source:
        terraform = hcl2.load(source)
    deployment_count = 0
    for resource_group in terraform.get('resource', []):
        for resource_type, resources in resource_group.items():
            for name, resource in resources.items():
                if resource_type == 'kubernetes_service_v1':
                    if resource['spec'][0].get('type', ['ClusterIP'])[0] != 'ClusterIP':
                        findings.append({'id': 'PROJECT_PUBLIC_SERVICE', 'resource': f'terraform.{name}',
                                         'message': 'Terraform service must use ClusterIP'})
                if resource_type == 'kubernetes_deployment_v1':
                    deployment_count += 1
                    spec = resource['spec'][0]['template'][0]['spec'][0]
                    pod_context = spec.get('security_context', [{}])[0]
                    for container in spec.get('container', []):
                        context = {**pod_context, **container.get('security_context', [{}])[0]}
                        uid = context.get('run_as_user', [None])[0]
                        non_root = context.get('run_as_non_root', [False])[0]
                        if not isinstance(uid, int) or uid <= 0 or non_root is not True:
                            findings.append({'id': 'PROJECT_NON_ROOT', 'resource': f'terraform.{name}',
                                             'message': 'Require a literal positive UID and run_as_non_root=true'})
    if deployment_count == 0:
        raise ValueError('Terraform deployment missing')
    return {'findings': findings, 'kubernetes_documents': len(documents), 'terraform_deployments': deployment_count}
