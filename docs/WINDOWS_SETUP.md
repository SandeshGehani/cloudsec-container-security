# Windows container setup

The project includes checksum-verified kind 0.33.0 and kubectl 1.37.0 executables in `.tools/bin`. Terraform 1.17.2 is already available there. The official Docker Desktop 4.99.0 installer is downloaded to `work/Docker-Desktop-Installer.exe`, and its Docker Inc Authenticode signature passed verification.

Administrator approval succeeded on 13 November 2026. Virtual Machine Platform and Windows Subsystem for Linux were enabled, and both returned `RestartNeeded: true`. WSL 3.0.5 and Docker Desktop installed successfully. The Docker CLI reports version 29.9.3. Windows must restart before the Linux engine can be verified.

## Enable the Windows prerequisites

The prerequisite step is complete on this laptop, with activation pending a restart. `work/wsl-features.json` records both restart requirements. The post-install WSL status check reports `Wsl/WSL_E_WSL_OPTIONAL_COMPONENT_REQUIRED` and directs a restart. The setup wrapper was corrected to capture native WSL stdout and stderr separately, so a restart message written to stderr is evaluated through the process exit code.

For a new Windows machine, run this command from an administrator PowerShell session in the project folder.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup_windows.ps1 -EnableWsl
```

The execution-policy option applies to the launched PowerShell process. Save your work and restart Windows when the prerequisite step finishes.

## Install Docker Desktop

Docker Desktop is already installed on this laptop. Save your work, restart Windows and start Docker Desktop from the Start menu. For a new installation, open PowerShell in `E:\Cloudsec_Project\container-security` and run the per-user setup command.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup_windows.ps1 -InstallDocker
```

The setup script verifies the pinned project tools and Docker's publisher signature before invoking its installer. Start Docker Desktop from the Start menu and wait for the Linux container engine to report ready.

## Verify the engine

```powershell
$env:PATH = "$PWD\.tools\bin;$env:LOCALAPPDATA\Programs\DockerDesktop\resources\bin;$env:PATH"
wsl --version
docker version
docker info --format '{{.OSType}}'
docker run --rm hello-world
```

The engine checks require a server version, an operating-system result of `linux`, and a successful hello-world container.

## Run the Kubernetes demonstration

Use a fresh Docker environment without an existing cluster named `container-security`. The verifier creates and cleans up its own cluster. It runs the YAML and Terraform deployments, captures runtime results and tests NetworkPolicy traffic across two nodes.

```powershell
.\.venv\Scripts\python.exe scripts\verify_cluster.py --output reports\windows-cluster-demo
```

Choose a new output directory for each run. The two-node Calico verification has already passed on GitHub-hosted Linux runners. Local engine and cluster verification are pending the Windows restart.

## Sources

- [Docker Desktop Windows installation and prerequisites](https://docs.docker.com/desktop/setup/install/windows-install/)
- [Microsoft WSL installation](https://learn.microsoft.com/en-us/windows/wsl/install)
- [Calico installation on kind](https://docs.tigera.io/calico/latest/getting-started/kubernetes/kind)
