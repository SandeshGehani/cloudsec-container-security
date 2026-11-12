#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$InstallDocker,
    [switch]$EnableWsl
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$projectWork = Join-Path $projectRoot 'work'
$toolDirectory = Join-Path $projectRoot '.tools\bin'
New-Item -ItemType Directory -Force -Path $projectWork, $toolDirectory | Out-Null

if ($EnableWsl) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Enabling WSL requires an administrator PowerShell session.'
    }
    Start-Transcript -LiteralPath (Join-Path $projectWork 'wsl-admin.log') -Append | Out-Null
    try {
        $featureResults = foreach ($featureName in @('VirtualMachinePlatform', 'Microsoft-Windows-Subsystem-Linux')) {
            Enable-WindowsOptionalFeature -Online -FeatureName $featureName -All -NoRestart
        }
        $featureResults | Select-Object Online, RestartNeeded | ConvertTo-Json |
            Set-Content -LiteralPath (Join-Path $projectWork 'wsl-features.json') -Encoding UTF8
        $wslInstaller = Start-Process -FilePath 'wsl.exe' -WindowStyle Hidden -PassThru -Wait `
            -ArgumentList '--install', '--no-distribution', '--web-download', '--no-launch' `
            -RedirectStandardOutput (Join-Path $projectWork 'wsl-install.log') `
            -RedirectStandardError (Join-Path $projectWork 'wsl-install-error.log')
        $wslExitCode = $wslInstaller.ExitCode
        Write-Output "WSL installer exit code $wslExitCode"
        Write-Output 'Save your work and restart Windows before checking the container engine.'
        if ($wslExitCode -notin @(0, 3010)) {
            throw "WSL installation needs attention. Review work\wsl-install.log and work\wsl-install-error.log. Exit code $wslExitCode"
        }
    } finally {
        Stop-Transcript | Out-Null
    }
    return
}

if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
    throw 'The pinned Windows cluster tools require an x86-64 host.'
}
$manifest = Get-Content -LiteralPath (Join-Path $projectRoot 'tools\cluster-windows-versions.json') -Raw |
    ConvertFrom-Json
foreach ($entry in $manifest.PSObject.Properties) {
    $destination = Join-Path $toolDirectory $entry.Name
    $specification = $entry.Value
    $alreadyValid = (Test-Path -LiteralPath $destination) -and
        ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -eq $specification.sha256)
    if (-not $alreadyValid) {
        $downloadPath = Join-Path $projectWork ($entry.Name + '.download')
        & curl.exe --fail --location --retry 3 --silent --show-error --output $downloadPath $specification.url
        if ($LASTEXITCODE -ne 0) {
            throw "Download failed for $($entry.Name)."
        }
        if ((Get-FileHash -LiteralPath $downloadPath -Algorithm SHA256).Hash -ne $specification.sha256) {
            throw "Checksum mismatch for $($entry.Name)."
        }
        Move-Item -LiteralPath $downloadPath -Destination $destination -Force
    }
    Write-Output "Verified $($entry.Name) $($specification.version)"
}

if ($InstallDocker) {
    $installer = Join-Path $projectWork 'Docker-Desktop-Installer.exe'
    if (-not (Test-Path -LiteralPath $installer)) {
        & curl.exe --fail --location --retry 3 --silent --show-error --output $installer `
            'https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe'
        if ($LASTEXITCODE -ne 0) {
            throw 'Docker Desktop download failed.'
        }
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $installer
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Docker Inc') {
        throw 'Docker Desktop installer requires a valid Docker Inc signature.'
    }
    $process = Start-Process -FilePath $installer -WindowStyle Hidden -PassThru -Wait `
        -ArgumentList 'install', '--user', '--quiet', '--accept-license', '--backend=wsl-2' `
        -RedirectStandardOutput (Join-Path $projectWork 'docker-install.log') `
        -RedirectStandardError (Join-Path $projectWork 'docker-install-error.log')
    Write-Output "Docker Desktop installer exit code $($process.ExitCode)"
    if ($process.ExitCode -ne 0) {
        throw 'Docker Desktop installation needs attention. Review work\docker-install.log and work\docker-install-error.log.'
    }
}

Write-Output 'Project tools are available in .tools\bin. Add that folder to PATH in the terminal used for the demo.'
