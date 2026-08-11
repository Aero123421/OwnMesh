# OwnMesh portable installer (Windows x64).
#
# Trust model (fail-closed):
#   1. Verify SHA256SUMS.minisig with minisign against the pinned OwnMesh public key
#      before trusting any checksum line.
#   2. Verify the archive SHA-256 from the trusted sums.
#   3. Extract only required binaries. Never evaluate remote script text in-process.
#
# The one-line bootstrap downloads this script to a local temporary path. Release
# binaries still require the independent OwnMesh signature below. Minisign itself
# is bootstrapped from a pinned archive hash when it is not already installed.

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
    $MinisignBin = $env:OWNMESH_MINISIGN
    $RequiredBinaries = @(
        "ownmesh.exe",
        "ownmesh-tui.exe",
        "ownmeshd.exe",
        "ownmesh-session-host.exe",
        "ownmesh-broker.exe"
    )

    # Pinned OwnMesh minisign trust root (docs/release-keys/minisign.pub).
    $PinnedMinisignPubComment = "untrusted comment: minisign public key C596813EFB0946A4"
    $PinnedMinisignPubKey = "RWSkRgn7PoGWxQVPfPTcZzF3P8Wi5JMb+EOydWtYYosHDIEsLUnGl8eI"
    $PinnedMinisignUrl = "https://github.com/jedisct1/minisign/releases/download/0.11/minisign-0.11-win64.zip"
    $PinnedMinisignSha256 = "b9c31c2c3034f81f0e5f5d92cbcc20e67a9671b6e5455661588638848dc58031"

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

    function Resolve-Minisign {
        param([Parameter(Mandatory)][string]$BootstrapDir)
        if ($MinisignBin) {
            if (-not (Test-Path -LiteralPath $MinisignBin -PathType Leaf)) {
                throw "OWNMESH_MINISIGN is not a file: $MinisignBin"
            }
            return $MinisignBin
        }
        $cmd = Get-Command minisign -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
        $cmd = Get-Command minisign.exe -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }

        Write-Host "Bootstrapping pinned minisign verifier..."
        Assert-SafeUrl $PinnedMinisignUrl
        $archive = Join-Path $BootstrapDir "minisign-0.11-win64.zip"
        Invoke-WebRequest -Uri $PinnedMinisignUrl -OutFile $archive -UseBasicParsing
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
        if ($actual -ne $PinnedMinisignSha256) {
            throw "pinned minisign bootstrap SHA-256 mismatch"
        }
        Add-Type -AssemblyName System.IO.Compression
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $verified = Join-Path $BootstrapDir "minisign.exe"
        $zip = [System.IO.Compression.ZipFile]::OpenRead($archive)
        try {
            $entry = $zip.GetEntry("minisign-win64/minisign.exe")
            if (-not $entry -or $entry.Length -le 0 -or $entry.Length -gt 33554432) {
                throw "pinned minisign.exe is missing or oversized"
            }
            $input = $entry.Open()
            try {
                $output = [System.IO.File]::Create($verified)
                try {
                    $buffer = New-Object byte[] 8192
                    $written = [uint64]0
                    while (($count = $input.Read($buffer, 0, $buffer.Length)) -gt 0) {
                        $written += [uint64]$count
                        if ($written -gt 33554432) { throw "pinned minisign.exe is oversized" }
                        $output.Write($buffer, 0, $count)
                    }
                } finally {
                    $output.Dispose()
                }
            } finally {
                $input.Dispose()
            }
        } finally {
            $zip.Dispose()
        }
        return $verified
    }

    function Assert-MinisignSums {
        param(
            [Parameter(Mandatory)][string]$SumsPath,
            [Parameter(Mandatory)][string]$SigPath,
            [Parameter(Mandatory)][string]$PubKeyPath,
            [Parameter(Mandatory)][string]$MinisignPath
        )
        if (-not (Test-Path -LiteralPath $SigPath -PathType Leaf)) {
            throw "SHA256SUMS.minisig missing (signature required; refusing unsigned checksums)"
        }
        if (-not (Test-Path -LiteralPath $PubKeyPath -PathType Leaf)) {
            throw "minisign public key missing"
        }
        if (-not $env:OWNMESH_MINISIGN_PUB) {
            $pubText = Get-Content -LiteralPath $PubKeyPath -Raw
            if ($pubText -notlike "*$PinnedMinisignPubKey*") {
                throw "minisign public key does not match the pinned OwnMesh trust root"
            }
        }
        & $MinisignPath -Vm $SumsPath -p $PubKeyPath -x $SigPath | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "minisign verification failed for SHA256SUMS"
        }
        Write-Host "minisign: SHA256SUMS signature ok"
    }

    # Archive contract (identical security intent to ownmesh-update).
    $MaxArchiveEntries = 64
    $MaxEntryUncompressedBytes = [uint64](256 * 1024 * 1024)
    $MaxTotalUncompressedBytes = [uint64](512 * 1024 * 1024)
    $AllowedDocFiles = @("LICENSE", "NOTICE", "README.md", "RELEASE_NOTES.md", "CHANGELOG.md")

    function Get-SafeZipMemberBase {
        param([Parameter(Mandatory)][string]$Name)
        if ([string]::IsNullOrWhiteSpace($Name)) {
            throw "Refusing empty archive member name"
        }
        $normalized = $Name -replace '\\', '/'
        if ($normalized.StartsWith("/") -or $normalized.Contains("..")) {
            throw "Archive refuses member '$Name' (traversal)"
        }
        $parts = $normalized.Split('/', [System.StringSplitOptions]::RemoveEmptyEntries)
        if ($parts.Count -lt 1 -or $parts.Count -gt 2) {
            throw "Archive refuses nested member '$Name'"
        }
        $base = $parts[$parts.Count - 1]
        if ([string]::IsNullOrWhiteSpace($base) -or $base.Contains("..") -or $base.Contains("/") -or $base.Contains("\")) {
            throw "Archive refuses member name '$base'"
        }
        return $base
    }

    function Test-AllowedMemberBase {
        param([Parameter(Mandatory)][string]$Base)
        foreach ($bin in $RequiredBinaries) {
            if ($Base -ceq $bin) { return $true }
        }
        foreach ($doc in $AllowedDocFiles) {
            if ($Base -ceq $doc) { return $true }
        }
        return $false
    }

    function Test-ZipEntryIsSymlink {
        param($Entry)
        # ZIP external attributes: high 16 bits are Unix mode when created on Unix.
        # Use decimal constants (Windows PowerShell 5.1 has no 0o octal literals).
        try {
            $ext = [uint32]$Entry.ExternalAttributes
            $mode = ($ext -shr 16) -band 0xFFFF
            $ifmt = $mode -band 61440   # 0o170000
            $iflnk = 49152              # 0o120000
            if ($ifmt -eq $iflnk) { return $true }
            # Non-regular, non-directory special types.
            $ifreg = 32768              # 0o100000
            $ifdir = 16384              # 0o040000
            if ($mode -ne 0 -and $ifmt -ne 0 -and $ifmt -ne $ifreg -and $ifmt -ne $ifdir) {
                return $true
            }
        } catch {
            # If attributes cannot be interpreted, continue with other checks.
        }
        return $false
    }

    # Validate the full zip contract before allocating/extracting any member payload.
    # Never uses Expand-Archive (full extract). Streams allow-listed members only.
    function Assert-ArchiveContractAndExtract {
        param(
            [Parameter(Mandatory)][string]$ArchivePath,
            [Parameter(Mandatory)][string]$DestinationDir
        )

        Add-Type -AssemblyName System.IO.Compression
        Add-Type -AssemblyName System.IO.Compression.FileSystem

        $zip = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
        try {
            if ($zip.Entries.Count -gt $MaxArchiveEntries) {
                throw "Archive entry count exceeds limit $MaxArchiveEntries"
            }

            $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
            $totalUncompressed = [uint64]0
            $planned = New-Object System.Collections.Generic.List[object]

            foreach ($entry in $zip.Entries) {
                $fullName = $entry.FullName
                if ([string]::IsNullOrWhiteSpace($fullName)) { continue }
                $normalized = $fullName -replace '\\', '/'
                if ($normalized.EndsWith("/")) {
                    # Directory entry — no payload retained.
                    continue
                }
                if (Test-ZipEntryIsSymlink -Entry $entry) {
                    throw "Refusing symlink/special archive member '$fullName'"
                }

                $base = Get-SafeZipMemberBase -Name $fullName
                if (-not (Test-AllowedMemberBase -Base $base)) {
                    throw "Refusing unexpected archive member $base"
                }
                if (-not $seen.Add($base)) {
                    throw "Refusing duplicate archive member $base"
                }

                $declared = [uint64]$entry.Length
                if ($declared -gt $MaxEntryUncompressedBytes) {
                    throw "Archive member $base exceeds per-entry limit $MaxEntryUncompressedBytes"
                }
                $totalUncompressed += $declared
                if ($totalUncompressed -gt $MaxTotalUncompressedBytes) {
                    throw "Archive total uncompressed size exceeds limit $MaxTotalUncompressedBytes"
                }

                $planned.Add([pscustomobject]@{
                        Base     = $base
                        Entry    = $entry
                        Declared = $declared
                    }) | Out-Null
            }

            foreach ($bin in $RequiredBinaries) {
                if (-not $seen.Contains($bin)) {
                    throw "Archive missing required binary $bin"
                }
            }

            New-Item -ItemType Directory -Force -Path $DestinationDir | Out-Null

            foreach ($item in $planned) {
                # Only stage required binaries for install; docs may be written too.
                $outPath = Join-Path $DestinationDir $item.Base
                $inStream = $item.Entry.Open()
                try {
                    $outStream = [System.IO.File]::Create($outPath)
                    try {
                        $buffer = New-Object byte[] 8192
                        $readTotal = [uint64]0
                        while (($n = $inStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                            $readTotal += [uint64]$n
                            if ($readTotal -gt $MaxEntryUncompressedBytes) {
                                throw "Archive member $($item.Base) exceeds per-entry limit $MaxEntryUncompressedBytes"
                            }
                            if ($item.Declared -gt 0 -and $readTotal -gt $item.Declared) {
                                throw "Archive member $($item.Base) expanded past declared size $($item.Declared)"
                            }
                            $outStream.Write($buffer, 0, $n)
                        }
                        if ($readTotal -eq 0 -and ($RequiredBinaries -contains $item.Base)) {
                            throw "Archive member $($item.Base) is empty"
                        }
                    } finally {
                        $outStream.Dispose()
                    }
                } finally {
                    $inStream.Dispose()
                }

                if ((Get-Item -LiteralPath $outPath).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                    throw "Extracted $($item.Base) is a reparse point; refusing"
                }
            }
        } finally {
            $zip.Dispose()
        }
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
        Net.SecurityProtocolType]::Tls12

    $tempDir = Join-Path ([IO.Path]::GetTempPath()) "ownmesh-install-$([Guid]::NewGuid().ToString('N'))"
    $archive = Join-Path $tempDir $asset
    $sums = Join-Path $tempDir "SHA256SUMS"
    $sig = Join-Path $tempDir "SHA256SUMS.minisig"
    $pubKey = Join-Path $tempDir "minisign.pub"
    $extractDir = Join-Path $tempDir "extract"
    $backupDir = Join-Path $InstallDir (".ownmesh-backup-" + [Guid]::NewGuid().ToString('N'))
    $stagedFiles = @()
    $replacedBins = @()
    $keepBackup = $false

    try {
        New-Item -ItemType Directory -Path $tempDir | Out-Null
        $minisignPath = Resolve-Minisign -BootstrapDir $tempDir

        Write-Host "Downloading $asset..."
        Copy-ReleaseAsset $asset $archive
        Copy-ReleaseAsset "SHA256SUMS" $sums
        Copy-ReleaseAsset "SHA256SUMS.minisig" $sig

        if ($env:OWNMESH_MINISIGN_PUB) {
            if (-not (Test-Path -LiteralPath $env:OWNMESH_MINISIGN_PUB -PathType Leaf)) {
                throw "OWNMESH_MINISIGN_PUB is not a file"
            }
            Copy-Item -LiteralPath $env:OWNMESH_MINISIGN_PUB -Destination $pubKey -Force
        } elseif ($AssetDir -and (Test-Path -LiteralPath (Join-Path $AssetDir "minisign.pub") -PathType Leaf)) {
            Copy-Item -LiteralPath (Join-Path $AssetDir "minisign.pub") -Destination $pubKey -Force
        } else {
            $repoPub = Join-Path $PSScriptRoot "..\docs\release-keys\minisign.pub"
            $beside = Join-Path $PSScriptRoot "minisign.pub"
            if (Test-Path -LiteralPath $repoPub -PathType Leaf) {
                Copy-Item -LiteralPath $repoPub -Destination $pubKey -Force
            } elseif (Test-Path -LiteralPath $beside -PathType Leaf) {
                Copy-Item -LiteralPath $beside -Destination $pubKey -Force
            } else {
                @($PinnedMinisignPubComment, $PinnedMinisignPubKey) |
                    Set-Content -LiteralPath $pubKey -Encoding ascii
            }
        }

        Assert-MinisignSums -SumsPath $sums -SigPath $sig -PubKeyPath $pubKey -MinisignPath $minisignPath

        $expected = Get-ChecksumFromSums -SumsPath $sums -AssetName $asset
        $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $expected) {
            throw "SHA-256 mismatch for $asset (expected $expected, got $actual)"
        }

        # Validate contract then stream members into a private staging dir (no Expand-Archive).
        Assert-ArchiveContractAndExtract -ArchivePath $archive -DestinationDir $extractDir

        $resolved = @{}
        foreach ($bin in $RequiredBinaries) {
            $direct = Join-Path $extractDir $bin
            if (-not (Test-Path -LiteralPath $direct -PathType Leaf)) {
                throw "Partial extract: missing $bin"
            }
            $resolved[$bin] = $direct
        }

        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
        New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
        foreach ($bin in $RequiredBinaries) {
            $current = Join-Path $InstallDir $bin
            if (Test-Path -LiteralPath $current) {
                if (-not (Test-Path -LiteralPath $current -PathType Leaf)) {
                    throw "Refusing existing non-file at $current"
                }
                $currentItem = Get-Item -LiteralPath $current -Force
                if (($currentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw "Refusing existing reparse point at $current"
                }
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
                $replacedBins += $bin
                if (-not (Test-Path -LiteralPath $finalPath -PathType Leaf)) {
                    throw "Installed target is not a file: $finalPath"
                }
                $installedItem = Get-Item -LiteralPath $finalPath -Force
                if (($installedItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw "Installed target is a reparse point: $finalPath"
                }
            }
        } catch {
            Write-Host "Atomic install failed; restoring backup..."
            $restoreFailed = $false
            foreach ($bin in $RequiredBinaries) {
                if ($replacedBins -notcontains $bin) {
                    continue
                }
                $bak = Join-Path $backupDir $bin
                if (Test-Path -LiteralPath $bak -PathType Leaf) {
                    try {
                        $restorePath = Join-Path $InstallDir $bin
                        $restoreStaged = Join-Path $InstallDir (".{0}.restore-{1}-{2}" -f $bin, $PID, ([Guid]::NewGuid().ToString('N')))
                        Copy-Item -LiteralPath $bak -Destination $restoreStaged -Force -ErrorAction Stop
                        $stagedFiles += $restoreStaged
                        if (Test-Path -LiteralPath $restorePath) {
                            if (-not (Test-Path -LiteralPath $restorePath -PathType Leaf)) {
                                throw "Rollback refused unsafe non-file target for $bin"
                            }
                            $restoreItem = Get-Item -LiteralPath $restorePath -Force
                            if (($restoreItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                                throw "Rollback refused unsafe reparse point for $bin"
                            }
                            $displacedPath = Join-Path $InstallDir (".{0}.failed-{1}-{2}" -f $bin, $PID, ([Guid]::NewGuid().ToString('N')))
                            $stagedFiles += $displacedPath
                            [IO.File]::Replace($restoreStaged, $restorePath, $displacedPath, $true)
                            Remove-Item -LiteralPath $displacedPath -Force -ErrorAction Stop
                        } else {
                            Move-Item -LiteralPath $restoreStaged -Destination $restorePath -ErrorAction Stop
                        }
                        $restoredHash = (Get-FileHash -LiteralPath $restorePath -Algorithm SHA256).Hash
                        $backupHash = (Get-FileHash -LiteralPath $bak -Algorithm SHA256).Hash
                        if ($restoredHash -ne $backupHash) {
                            throw "Rollback verification failed for $bin"
                        }
                    } catch {
                        Write-Host "Rollback failed for $bin"
                        $restoreFailed = $true
                    }
                } else {
                    $newPath = Join-Path $InstallDir $bin
                    if (Test-Path -LiteralPath $newPath) {
                        try {
                            Remove-Item -LiteralPath $newPath -Force -ErrorAction Stop
                        } catch {
                            Write-Host "Rollback failed to remove newly installed $bin"
                            $restoreFailed = $true
                        }
                    }
                }
            }
            if ($restoreFailed) {
                $keepBackup = $true
                throw "Install failed and backup rollback also failed (backup left at $backupDir)"
            }
            throw
        }

        if (Test-Path -LiteralPath $backupDir) {
            Remove-Item -LiteralPath $backupDir -Recurse -Force -ErrorAction Stop
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
        if (-not $keepBackup -and (Test-Path -LiteralPath $backupDir)) {
            Remove-Item -LiteralPath $backupDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $tempDir) {
            Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
