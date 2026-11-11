# Container security demonstration

Allow about ten minutes. Open the presentation, the project folder and both verified GitHub runs before starting.

- [Release and publication](https://github.com/SandeshGehani/cloudsec-container-security/actions/runs/43103995163)
- [Repeated evaluation and Kubernetes verification](https://github.com/SandeshGehani/cloudsec-container-security/actions/runs/43103995123)

## Explain the project

Say “We built an automated container security pipeline. The same Flask task tracker has an insecure baseline and a hardened container configuration. The pipeline combines Dockerfile checks, infrastructure checks, image vulnerability scanning, secret detection and an image audit. A central gate controls release publication.”

Show `Dockerfile.baseline`, `Dockerfile`, and the two Kubernetes manifests. Point to the old dependency pins, implicit root identity, fictional secret and privileged baseline deployment. Then show UID 10001, the multi-stage build, removal of runtime pip, restricted security context and health probes in the hardened configuration.

## Show the failing baseline

Open `reports/evaluation-baseline/cold-1/report.html` and `gate.json`.

- The security gate is FAIL with 4,981 blocking records and zero collection errors.
- Show one fixable vulnerability, the secret fixture and the root-user result.
- Explain that findings can overlap across scanners and packages. The blocker count combines vulnerability and configuration records.

The GitHub baseline evaluation job is green because evidence collection succeeded. Its job summary and retained `gate.json` explicitly show the failed security gate. To show the collector's failing process status on a Linux machine with Docker and the installed tools, use a fresh evidence directory.

```bash
python scripts/run_pipeline.py --variant baseline --reports reports/live-baseline
echo $?
```

The expected exit code is 1 when scans complete and the baseline gate fails. A future database update can change the finding counts. The report directory must be new for each attempt.

## Show the hardened release

Open `reports/evaluation-hardened/cold-1/report.html` and `gate.json`. Show PASS, zero blockers and zero collection errors. In the verified release run, show the successful hardened job and publish job. The publication step verifies that the image ID matches the scanned artifact before pushing the commit-SHA tag.

The policy permits zero fixable HIGH or CRITICAL findings from either vulnerability scanner. It also blocks secrets, root execution, fatal Dockle findings, Hadolint errors, failed required infrastructure checks and missing or failed collection evidence. Unfixed vulnerabilities remain in the reports for review. The exceptions list is empty.

## Compare the results

Use the presentation charts and `docs/evaluation-summary.json`.

| Measurement | Baseline | Hardened |
| --- | --- | --- |
| Measured security gates | FAIL in 6 of 6 | PASS in 6 of 6 |
| Cold median collector time | 92.070 seconds | 79.325 seconds |
| Warm median collector time | 33.631 seconds | 14.206 seconds |
| Cold and warm sample size | 3 each | 3 each |
| First cold trial blockers | 4,981 | 0 |
| Alias-normalised shared advisory IDs | 1,396 | 120 |

Cold trials disable Docker build-cache use and select fresh vulnerability-database directories. Base-image layers can remain locally available. Each variant runs on a separate hosted runner. Setup, tool installation and artifact publication fall outside collector duration.

Explain that advisory-ID overlap and package-vulnerability counts measure different things. An unmatched scanner finding requires investigation. `docs/overlap.json` includes exact-ID, explicit-alias and package-level comparisons.

Use two examples from `docs/triage.json` if asked about false positives. The Werkzeug path advisory requires Windows with an older Python version. The scanned baseline is Linux. Debian's MiniZip qualification also excludes the affected code from the reported Bookworm zlib binary package. The ten-record purposive sample supports case analysis and has no population false-positive-rate estimate.

## Show the application

From `E:\Cloudsec_Project\container-security` run the existing local environment in PowerShell.

```powershell
$env:DATABASE_PATH = "$PWD\work\taskboard-demo\tasks.db"
.\.venv\Scripts\python.exe -m flask --app app/app.py run --host 127.0.0.1 --port 8080
```

Open [Taskboard](http://127.0.0.1:8080), add a task and mark it complete. Open [the health endpoint](http://127.0.0.1:8080/healthz). Stop the server with Ctrl+C afterwards.

## Show deployment evidence

Open `reports/networkpolicy-verification/verification.json` and `taskboard-hardened.png`. The [follow-up hosted workflow](https://github.com/SandeshGehani/cloudsec-container-security/actions/runs/43110425889) deployed both YAML and Terraform definitions to a disposable two-node kind cluster with Calico 3.33.0. It verified a ready pod, UID 10001, health and task creation, and rejected a root filesystem write. It checked disabled privileges, dropped capabilities and disabled service account token mounting. Terraform created four resources in its own namespace. The workflow deleted the cluster after verification.

Show `docs/networkpolicy-verification.json`. All 16 cross-node traffic checks passed across both deployment definitions. Same-namespace clients reached the app. Clients in another namespace timed out, and the app's outgoing connections timed out. Removing each policy made the blocked paths reachable. Restoring it blocked them again. Every check required two consecutive matching observations.

Windows kind and kubectl tools are ready in `.tools/bin`. Docker Desktop installation requires administrator approval to enable Virtual Machine Platform and WSL, followed by a Windows restart. See `docs/WINDOWS_SETUP.md` for the prepared commands and engine checks.

To repeat the hosted deployment, open the **Evaluation and Kubernetes demonstration** workflow, choose **Run workflow**, and select main. The workflow also repeats both timing evaluations. Review its retained `kubernetes-demo`, `evaluation-baseline` and `evaluation-hardened` artifacts.

## Questions to rehearse

**Why use both Trivy and Grype?** They use different inventories and matching sources. The first hardened attempt showed Trivy findings in libraries bundled inside pip that produced no matching Grype blockers through the Syft SBOM. The project preserves each tool's output and measures overlap.

**Does a passing gate mean there are zero vulnerabilities?** The gate evaluates the agreed policy. Unfixed findings remain visible. The hardened image had zero observed fixable HIGH or CRITICAL blockers in these measured runs.

**How are reports preserved after a failure?** Independent stages continue collecting, and artifact upload runs even after failed gates. Missing required evidence rejects publication.

**What is the infrastructure scope?** A namespace, Deployment, ClusterIP Service and NetworkPolicy through Kubernetes YAML and the Terraform Kubernetes provider. Hosted kind supplies the verified cluster.

**What comes next?** Complete laptop Docker and WSL setup if a local container demo is required, then rehearse the explanation. Runtime protection, signing and admission control are future work listed in the proposal.
