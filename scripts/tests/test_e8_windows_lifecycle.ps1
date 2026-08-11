# Opt-in, Administrator-only receipt for the Windows SCM broker lifecycle.
# It is intentionally never invoked by cross-platform CI: running it changes
# real SCM state and requires an already-installed/running OwnMeshDaemon.
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [string]$Broker,
    [switch]$UninstallAfter
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'E8 Windows lifecycle receipt requires an elevated Administrator PowerShell session.'
}
if (-not (Test-Path -LiteralPath $Broker -PathType Leaf)) {
    throw "Broker binary not found: $Broker"
}

# Repair only the known failed non-admin test residue. Never remove a real
# custody configuration or any caller-supplied path.
$leakedBrokerDir = Join-Path $env:ProgramData 'OwnMesh\broker'
$leakedConfig = Join-Path $leakedBrokerDir 'broker-service.json'
if ((Test-Path -LiteralPath $leakedBrokerDir -PathType Container) -and -not (Test-Path -LiteralPath $leakedConfig -PathType Leaf)) {
    $resolvedLeak = [IO.Path]::GetFullPath($leakedBrokerDir)
    $expectedLeak = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'OwnMesh\broker'))
    if ($resolvedLeak -ne $expectedLeak) { throw 'refusing unexpected broker cleanup target' }
    if ($PSCmdlet.ShouldProcess($resolvedLeak, 'remove exact leaked non-admin E8 custody directory')) {
        Remove-Item -LiteralPath $resolvedLeak -Recurse -Force
    }
}
if ((sc.exe query OwnMeshDaemon) -notmatch 'RUNNING') {
    throw 'OwnMeshDaemon must already be installed and RUNNING; this broker-only receipt never installs ownmeshd.'
}

if ($PSCmdlet.ShouldProcess('OwnMeshPrivilegedBroker', 'install/start and verify SCM lifecycle')) {
    & $Broker install
    if ($LASTEXITCODE -ne 0) { throw 'broker install failed' }
    & $Broker status
    if ($LASTEXITCODE -ne 0) { throw 'broker status failed after install' }
    sc.exe stop OwnMeshPrivilegedBroker | Out-Host
    Start-Sleep -Milliseconds 500
    if ((sc.exe query OwnMeshPrivilegedBroker) -match 'RUNNING') { throw 'broker remained RUNNING after SCM stop' }
    sc.exe start OwnMeshPrivilegedBroker | Out-Host
    Start-Sleep -Milliseconds 500
    if ((sc.exe query OwnMeshPrivilegedBroker) -notmatch 'RUNNING') { throw 'broker did not reach RUNNING after SCM start' }

    # Receipts are evidence, not a broker-managed artifact. Keeping them
    # outside `OwnMesh\broker` means a successful uninstall can remove the
    # complete managed root without a retained receipt making it look foreign.
    $receiptDir = Join-Path $env:ProgramData 'OwnMesh\receipts'
    New-Item -ItemType Directory -Force -Path $receiptDir | Out-Null
    $receipt = [ordered]@{
        schema_version = 1
        check = 'e8-windows-broker-lifecycle'
        utc = [DateTime]::UtcNow.ToString('o')
        broker = (Resolve-Path -LiteralPath $Broker).Path
        daemon_service = 'OwnMeshDaemon'
        broker_service = 'OwnMeshPrivilegedBroker'
        status = 'passed'
    } | ConvertTo-Json
    $receiptPath = Join-Path $receiptDir 'e8-windows-lifecycle.json'
    Set-Content -LiteralPath $receiptPath -Value $receipt -NoNewline -Encoding utf8
    & icacls.exe $receiptDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    Write-Output "E8 Windows lifecycle receipt: $receiptPath"

    if ($UninstallAfter) {
        & $Broker uninstall
        if ($LASTEXITCODE -ne 0) { throw 'broker uninstall failed' }
        if ((sc.exe query OwnMeshPrivilegedBroker) -notmatch 'FAILED 1060') { throw 'broker SCM service still exists after uninstall' }
    }
}
