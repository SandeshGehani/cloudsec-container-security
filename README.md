# Automated DevSecOps Pipeline for Container Security

This project builds and evaluates a container security pipeline around a small Flask task tracker. GitHub Actions collects evidence from Hadolint, Checkov, Trivy, Syft, Grype, and Dockle. One final policy gate determines whether the hardened image can be published to GitHub Container Registry.

The baseline intentionally includes an old Python image, outdated application dependencies, implicit root execution, a fake demonstration token, and a privileged Kubernetes deployment referencing a mutable `latest` tag. The hardened configuration uses current pinned dependencies, a multi-stage build, UID 10001, resource limits, probes, a read-only container filesystem, and a restricted security context. Package installation runs in the build stage, and the runtime image removes pip and its bundled bootstrap installer.

## Current implementation

- The application supports adding tasks, completing tasks, and checking `/healthz`.
- Baseline and hardened Dockerfiles and Kubernetes manifests are included.
- Terraform manages a namespace, Deployment, ClusterIP Service, and NetworkPolicy through the Kubernetes provider.
- The pipeline preserves reports after security failures and records stage timings, tool versions, database metadata, and image identity.
- Regression tests cover app behaviour, vulnerability thresholds, root execution, missing reports, scanner failures, and skipped required checks.
- An automated comparison records vulnerability counts, exact-ID overlap, image size, and pipeline durations.

Container builds, scanner execution against images, registry publication, and cluster deployment require verification in an environment with Docker. The final evaluation report and presentation depend on collecting those results.

## Run the app on Windows

From the project folder, create an environment and install the application dependencies.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:DATABASE_PATH = "$PWD\work\taskboard\tasks.db"
.\.venv\Scripts\python.exe -m flask --app app/app.py run --host 127.0.0.1 --port 8080
```

Open [Taskboard](http://127.0.0.1:8080). This is a single-user demonstration app with SQLite storage. The container stores its database under `/tmp/taskboard`. Kubernetes uses an `emptyDir` volume, so task data lasts for the pod's lifetime.

## Run the regression checks

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-tools.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## Run the container pipeline locally

Use Linux x86-64 or WSL2 with Python 3.13, Git, Docker Engine, and Docker Buildx available. On Windows, Docker Desktop with WSL integration supplies the container environment. The scanner installer downloads fixed releases and checks their SHA-256 values against `tools/versions.json`.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-tools.txt
python -m pip install 'checkov==3.4.4'
python scripts/install_tools.py
python scripts/run_pipeline.py --variant baseline --reports reports/baseline-01
python scripts/run_pipeline.py --variant hardened --reports reports/hardened-01
```

The baseline command returns exit code 1 when its security gate rejects the image. Run each command individually so the baseline failure allows you to inspect its evidence and continue the comparison.

Every invocation requires a fresh report directory. This preserves the connection between each report and the run that produced it. `--no-cache` disables Docker build-cache use and selects fresh vulnerability database directories for that run.

```bash
python scripts/run_pipeline.py --variant baseline --reports reports/baseline-cold --no-cache
python scripts/run_pipeline.py --variant hardened --reports reports/hardened-cold --no-cache
python scripts/report.py --baseline reports/baseline-01 --hardened reports/hardened-01 --output reports/comparison.json
```

The hardened image may still produce blocking findings as vulnerability databases change. Its gate result must be established by an actual scan, followed by remediation or a documented risk exception.

## Security policy

Both vulnerability scanners use the same rules. Any fixable HIGH or CRITICAL vulnerability blocks publication. HIGH and CRITICAL findings without an available fix remain visible for review. Vulnerability counts are deduplicated by tool, identifier, package name, and installed version.

Detected secrets, an implicit or zero runtime UID, fatal Dockle findings, Hadolint error-level findings, and failed required infrastructure checks also block publication. The image policy requires a positive numeric UID, which lets the gate validate identity from image metadata.

`policy/gates.json` lists the Checkov checks required by this project. Other Checkov findings remain in the raw reports for review. The required list covers probes, resources, privilege restrictions, filesystem permissions, capabilities, and runtime identity where each scanner framework supports them. `scripts/infra_policy.py` additionally validates non-root execution and ClusterIP-only services in YAML and Terraform.

An operational failure always rejects the release. Examples include a failed build, a scanner crash, a missing report, a vulnerability database failure, invalid report JSON, or an absent required Checkov check. Required skipped checks also reject the release. Scan commands collect findings without immediately stopping the remaining stages. A failed image build marks image-dependent checks unavailable.

Reviewed risk exceptions are exact matches in the central policy. Each entry must include these fields.

```json
{
  "tool": "trivy",
  "rule": "CVE-EXAMPLE",
  "subject": "package-name",
  "justification": "Specific risk analysis and compensating control",
  "review_date": "2026-12-01"
}
```

Add an approved entry to the `exceptions` array. Expired or malformed exceptions fail the gate. Operational failures remain blocking. Keep the raw scanner results intact for the comparison study.

The baseline dummy token is deliberately fictional. Its custom detection rule in `policy/trivy-secret.yaml` provides repeatable secret-scanning evidence alongside Trivy's built-in rules.

## GitHub Actions

Push this project to a GitHub repository with `main` as its release branch. The workflow runs on branch pushes, pull requests, and manual dispatch. Repository access and package publication use the workflow's `GITHUB_TOKEN`.

The reusable scan workflow processes each variant independently. The baseline evaluation job permits policy findings while still failing on evidence-collection errors. Its retained `gate.json`, HTML report, and job summary explicitly show the failed security gate. The hardened job enforces the gate through its exit status. Running the baseline CLI command locally provides the failing-process demonstration.

Publication requires the application tests and hardened scan job to succeed on a push to `main`. The publication job loads the saved scanned image, verifies its image ID against the scan evidence, and pushes that exact image with a commit-SHA tag.

```text
ghcr.io/<owner>/<repository>:<commit-sha>
```

Evidence artifacts are retained for 30 days. The hardened image archive is retained for one day for the publication handoff. SARIF is retained as an artifact and uploaded to GitHub code scanning on branch pushes and manual runs targeting both versions. The repository must support code scanning. The SARIF upload job has its own status.

Manual dispatch allows selecting baseline, hardened, or both versions, and toggling caches. Collect at least one cold and one warm run per variant, with repeated runs for a meaningful timing comparison. Record GitHub run URLs and the database timestamps from `trivy-version.json` and `grype-db.json`.

## Local Kubernetes demonstration

Create the named kind cluster and load the hardened image.

```bash
kind create cluster --name container-security --config infra/kind.yaml
docker buildx build --load --file Dockerfile --tag taskboard:hardened .
kind load docker-image taskboard:hardened --name container-security
kubectl --context kind-container-security apply -f infra/kubernetes/hardened/app.yaml
kubectl --context kind-container-security -n taskboard-hardened rollout status deployment/taskboard
kubectl --context kind-container-security -n taskboard-hardened port-forward service/taskboard 8080:8080
```

The service is accessible through the loopback port forward. Runtime NetworkPolicy enforcement requires a compatible CNI. kind's default CNI provides a local environment for this project's static policy evaluation.

Terraform provides the equivalent hardened deployment in its own namespace. Load the image into kind first, then run these commands from the project folder.

```bash
terraform -chdir=infra/terraform init
terraform -chdir=infra/terraform validate
terraform -chdir=infra/terraform plan
terraform -chdir=infra/terraform apply
```

Review the plan before approving the apply. The provider defaults to the `kind-container-security` context. The included Terraform dependency lock file records the verified provider selection.

## Evaluation and next milestones

1. Verify both container builds and complete image scans in Docker or GitHub Actions.
2. Review every hardened blocking finding and commit each remediation separately.
3. Collect baseline and hardened results close together in time, recording database timestamps.
4. Compare per-tool severities, exact vulnerability-ID overlap, image sizes, and stage durations.
5. Manually review a documented sample of findings for false positives. Record evidence and triage decisions.
6. Repeat with cold and warm caches and record the run-to-run variation.
7. Prepare the final report, presentation, and failing-then-passing demonstration from measured evidence.

Exact-ID overlap can undercount matches when one scanner reports a CVE and the other reports a GHSA alias. Manual review should account for aliases before interpreting scanner uniqueness.

Collector timings cover the stages in `run.json`. Record the GitHub job's total elapsed time separately to include environment setup, report uploads, and other workflow overhead.

## Tool documentation

- Dockerfile linting is documented by [Hadolint](https://github.com/hadolint/hadolint).
- Infrastructure checks are listed in [Checkov's Kubernetes policy index](https://www.checkov.io/5.Policy%20Index/kubernetes.html).
- Image report formats are described in [Trivy's reporting guide](https://trivy.dev/docs/dev/guide/configuration/reporting/).
- SBOM generation and vulnerability matching are documented by [Syft](https://github.com/anchore/syft) and [Grype](https://oss.anchore.com/docs/guides/vulnerability/filter-results/).
- Container image audit levels are described by [Dockle](https://github.com/goodwithtech/dockle).
