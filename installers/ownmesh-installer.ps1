# OwnMesh portable installer (Windows x64).
# Verifies SHA-256 before atomic per-user install.
# Security: never evaluate remote script text; download only to files via Invoke-WebRequest.

& {
    Set-StrictMode -Version Latest
    $ErrorActionPreference = "Stop"
    $ProgressPreference = "SilentlyContinue"

    $Repository = "Aero123421/OwnMesh"
    $RequestedVersion = if ($env:OWNMESH_VERSION) { $env:OWNMESH_VERSION } else { "latest" }
    $InstallDir = if ($env:OWNMESH_INSTALL_DIR) {
        $env:OWNMESH_INSTALL_DIR
    } else {
        Join-Path $env:LOCALAPPDATA "Programs\OwnMesh"
    }
    $AssetDir = $env:OWNMESH_ASSET_DIR
    $BaseUrlOverride = $env:OWNMESH_BASE_URL
    $RequiredBinaries = @(
        "ownmesh.exe",
        "ownmesh-tui.exe",
        "ownmeshd.exe",
        "ownmesh-session-host.exe",
        "ownmesh-broker.exe"
    )

    function Test-Injection {
        param([Parameter(Mandatory)][string]$Label, [Parameter(Mandatory)][string]$Value)
        if ($Value -match '[\r\n`$|&;<>]') {
            throw "Refusing $Label with shell metacharacters"
        }
    }

    function Normalize-Version {
        param([Parameter(Mandatory)][string]$Version)
        if ($Version -eq "latest") { return "latest" }
        if ($Version -notmatch '^v?\d+\.\d+\.\d+(?:[-.][0-9A-Za-z.-]+)?$') {
            throw "Invalid OWNMESH_VERSION '$Version' (expected latest, 1.2.3, or v1.2.3)"
        }
        if ($Version.StartsWith("v", [StringComparison]::Ordinal)) { return $Version }
        return "v$Version"
    }

    function Assert-SafeUrl {
        param([Parameter(Mandatory)][string]$Url)
        $uri = [Uri]$Url
        if ($uri.Scheme -ne "https") { throw "Refusing non-https URL" }
        if (-not [string]::IsNullOrEmpty($uri.UserInfo)) { throw "Refusing URL with userinfo" }
        if ($Url.Contains("..")) { throw "Refusing URL containing .." }
        $hostName = $uri.Host.ToLowerInvariant()
        $allowed = @(
            "github.com",
            "objects.githubusercontent.com",
            "release-assets.githubusercontent.com",
            "github-releases.githubusercontent.com"
        )
        $ok = $false
        foreach ($a in $allowed) {
            if ($hostName -eq $a -or $hostName.EndsWith(".$a")) { $ok = $true; break }
        }
        if (-not $ok) { throw "OWNMESH_BASE_URL host is not on the GitHub release allow-list: $hostName" }
    }

    function Copy-ReleaseAsset {
        param(
            [Parameter(Mandatory)][string]$Name,
            [Parameter(Mandatory)][string]$Destination
        )
        if ($Name -match '[\\/]|\.\.') {
            throw "Refusing unsafe asset name '$Name'"
        }
        if ($AssetDir) {
            if (-not (Test-Path -LiteralPath $AssetDir -PathType Container)) {
                throw "OWNMESH_ASSET_DIR is not a directory: $AssetDir"
            }
            $source = Join-Path $AssetDir $Name
            if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
                throw "Asset not found in OWNMESH_ASSET_DIR: $Name"
            }
            Copy-Item -LiteralPath $source -Destination $Destination
            return
        }
        $url = "$BaseUrl/$Name"
        Assert-SafeUrl $url
        try {
            Invoke-WebRequest -Uri $url -OutFile $Destination -UseBasicParsing
        } catch {
            throw "Download failed for $Name (HTTP error or 404)"
        }
    }

    function Get-ChecksumFromSums {
        param(
            [Parameter(Mandatory)][string]$SumsPath,
            [Parameter(Mandatory)][string]$AssetName
        )
        foreach ($line in Get-Content -LiteralPath $SumsPath) {
            $trim = $line.Trim()
            if (-not $trim -or $trim.StartsWith("#")) { continue }
            $parts = $trim -split '\s+', 2
            if ($parts.Count -lt 2) { continue }
            $digest = $parts[0].ToLowerInvariant()
            $name = $parts[1].TrimStart('*')
            if ($digest -notmatch '^[0-9a-f]{64}$') { continue }
            if ($name -eq $AssetName) { return $digest }
        }
        throw "SHA256SUMS missing entry for $AssetName"
    }

    function Test-SafeZipEntry {
        param([Parameter(Mandatory)][string]$Name)
        if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
        $normalized = $Name -replace '\\', '/'
        if ($normalized.StartsWith("/") -or $normalized.Contains("..")) { return $false }
        $parts = $normalized.Split('/', [System.StringSplitOptions]::RemoveEmptyEntries)
        if ($parts.Count -lt 1 -or $parts.Count -gt 2) { return $false }
        return $true
    }

    Test-Injection -Label "OWNMESH_VERSION" -Value $RequestedVersion
    Test-Injection -Label "OWNMESH_INSTALL_DIR" -Value $InstallDir
    if ($AssetDir) { Test-Injection -Label "OWNMESH_ASSET_DIR" -Value $AssetDir }
    if ($BaseUrlOverride) {
        Test-Injection -Label "OWNMESH_BASE_URL" -Value $BaseUrlOverride
        Assert-SafeUrl $BaseUrlOverride
    }

    $version = Normalize-Version $RequestedVersion
    $architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    switch ($architecture) {
        "X64" { }
        "Arm64" {
            Write-Host "Native Windows arm64 is not published yet; installing the Windows x64 build."
        }
        default {
            throw "Unsupported Windows CPU architecture '$architecture'"
        }
    }

    $asset = "ownmesh-windows-x64.zip"
    if ($BaseUrlOverride) {
        $BaseUrl = $BaseUrlOverride.TrimEnd("/")
    } elseif ($version -eq "latest") {
        $BaseUrl = "https://github.com/$Repository/releases/latest/download"
    } else {
        $BaseUrl = "https://github.com/$Repository/releases/download/$version"
    }
    Assert-SafeUrl "$BaseUrl/SHA256SUMS"

    # Force TLS 1.2+
    [Net.ServicePointManager]::SecurityProtocol = [
        Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

    $tempDir = Join-Path ([IO.Path]::GetTempPath()) "ownmesh-install-$([Guid]::NewGuid().ToString('N'))"
    $archive = Join-Path $tempDir $asset
    $sums = Join-Path $tempDir "SHA256SUMS"
    $extractDir = Join-Path $tempDir "extract"
    $backupDir = Join-Path $InstallDir (".ownmesh-backup-" + $PID)
    $stagedFiles = @()

    try {
        New-Item -ItemType Directory -Path $tempDir | Out-Null

        Write-Host "Downloading $asset..."
        Copy-ReleaseAsset $asset $archive
        Copy-ReleaseAsset "SHA256SUMS" $sums

        $expected = Get-ChecksumFromSums -SumsPath $sums -AssetName $asset
        $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $expected) {
            throw "SHA-256 mismatch for $asset (expected $expected, got $actual)"
        }

        New-Item -ItemType Directory -Path $extractDir | Out-Null
        # Expand then validate members (refuse traversal).
        Expand-Archive -LiteralPath $archive -DestinationPath $extractDir
        Get-ChildItem -LiteralPath $extractDir -Recurse -File | ForEach-Object {
            $rel = $_.FullName.Substring($extractDir.Length).TrimStart('\', '/')
            if (-not (Test-SafeZipEntry -Name $rel)) {
                throw "Archive refuses member '$rel' (traversal)"
            }
        }

        $resolved = @{}
        foreach ($bin in $RequiredBinaries) {
            $direct = Join-Path $extractDir $bin
            if (Test-Path -LiteralPath $direct -PathType Leaf) {
                $resolved[$bin] = $direct
                continue
            }
            $found = Get-ChildItem -LiteralPath $extractDir -Recurse -Filter $bin -File -ErrorAction SilentlyContinue |
                Select-Object -First 1
            if (-not $found) {
                throw "Archive missing required binary $bin"
            }
            $rel = $found.FullName.Substring($extractDir.Length).TrimStart('\', '/')
            if (-not (Test-SafeZipEntry -Name $rel)) {
                throw "Archive refuses member '$rel' (traversal)"
            }
            $resolved[$bin] = $found.FullName
        }

        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
        New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
        foreach ($bin in $RequiredBinaries) {
            $current = Join-Path $InstallDir $bin
            if (Test-Path -LiteralPath $current -PathType Leaf) {
                Copy-Item -LiteralPath $current -Destination (Join-Path $backupDir $bin) -Force
            }
        }

        try {
            foreach ($bin in $RequiredBinaries) {
                $staged = Join-Path $InstallDir (".{0}.new-{1}-{2}" -f $bin, $PID, ([Guid]::NewGuid().ToString('N')))
                Copy-Item -LiteralPath $resolved[$bin] -Destination $staged -Force
                Unblock-File -LiteralPath $staged -ErrorAction SilentlyContinue
                $stagedFiles += $staged
                $finalPath = Join-Path $InstallDir $bin
                Move-Item -LiteralPath $staged -Destination $finalPath -Force
            }
        } catch {
            Write-Host "Atomic install failed; restoring backup..."
            foreach ($bin in $RequiredBinaries) {
                $bak = Join-Path $backupDir $bin
                if (Test-Path -LiteralPath $bak -PathType Leaf) {
                    Copy-Item -LiteralPath $bak -Destination (Join-Path $InstallDir $bin) -Force
                }
            }
            throw
        }

        if (Test-Path -LiteralPath $backupDir) {
            Remove-Item -LiteralPath $backupDir -Recurse -Force -ErrorAction SilentlyContinue
        }

        $env:Path = "$InstallDir;$env:Path"
        if ($env:OWNMESH_NO_MODIFY_PATH -notin @("1", "true", "TRUE", "yes", "YES")) {
            $userPath = [string][Environment]::GetEnvironmentVariable("Path", "User")
            $normalizedInstallDir = $InstallDir.TrimEnd("\")
            $alreadyPresent = ($userPath -split ";") |
                Where-Object {
                    $_ -and $_.TrimEnd("\").Equals(
                        $normalizedInstallDir,
                        [StringComparison]::OrdinalIgnoreCase
                    )
                }
            if (-not $alreadyPresent) {
                $newUserPath = if ([string]::IsNullOrWhiteSpace($userPath)) {
                    $InstallDir
                } else {
                    "$userPath;$InstallDir"
                }
                [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
                Write-Host "Added `"$InstallDir`" to the user PATH."
            }
        }

        $ownmeshPath = Join-Path $InstallDir "ownmesh.exe"
        $installedVersion = & $ownmeshPath --version
        if ($LASTEXITCODE -ne 0) {
            throw "Installed binary did not start (--version smoke failed)"
        }
        Write-Host "Installed $installedVersion to $ownmeshPath"
        foreach ($bin in $RequiredBinaries) {
            Write-Host "  - $(Join-Path $InstallDir $bin)"
        }
    } finally {
        foreach ($staged in $stagedFiles) {
            if ($staged -and (Test-Path -LiteralPath $staged)) {
                Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
            }
        }
        if (Test-Path -LiteralPath $tempDir) {
            Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
