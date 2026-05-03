# singbox2proxy installer for Windows
# Supports two modes:
#   standalone (default) — downloads pre-built binary, no Python needed
#   python               — installs via pip, requires Python 3.9+
#
# Usage:
#   irm https://raw.githubusercontent.com/nichind/singbox2proxy/main/scripts/install.ps1 | iex
#
# With mode:
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/nichind/singbox2proxy/main/scripts/install.ps1))) -Mode standalone
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/nichind/singbox2proxy/main/scripts/install.ps1))) -Mode python
param(
    [ValidateSet("standalone", "python")]
    [string]$Mode = "standalone"
)

$ErrorActionPreference = "Stop"
$REPO = "nichind/singbox2proxy"
$BIN_NAME = "sb2p"
$BIN_ALIAS = "singbox2proxy"

# Install directory: %LOCALAPPDATA%\sb2p or custom
$INSTALL_DIR = if ($env:SB2P_INSTALL_DIR) { $env:SB2P_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "sb2p" }

Write-Host "==> singbox2proxy installer (mode: $Mode)" -ForegroundColor Cyan

# --- Ensure install dir in PATH ---
function Ensure-InPath {
    if (-not (Test-Path $INSTALL_DIR)) {
        New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null
    }

    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$INSTALL_DIR*") {
        $newPath = "$INSTALL_DIR;$userPath"
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
        $env:Path = "$INSTALL_DIR;$env:Path"
        Write-Host "==> Added $INSTALL_DIR to user PATH" -ForegroundColor Green
    }
}

# --- Create alias (copy exe with different name) ---
function Create-Aliases {
    param([string]$Source)

    $dir = Split-Path $Source -Parent
    $ext = [IO.Path]::GetExtension($Source)

    $name1 = Join-Path $dir "$BIN_NAME$ext"
    $name2 = Join-Path $dir "$BIN_ALIAS$ext"

    if ($Source -ne $name1) { Copy-Item -Path $Source -Destination $name1 -Force }
    if ($Source -ne $name2) { Copy-Item -Path $Source -Destination $name2 -Force }
}

# ===========================================================
# STANDALONE MODE
# ===========================================================
function Install-Standalone {
    Write-Host "==> Detecting platform..."

    $arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
    # Check for ARM
    $cpuArch = $env:PROCESSOR_ARCHITECTURE
    if ($cpuArch -eq "ARM64") { $arch = "arm64" }

    Write-Host "==> Platform: windows-$arch"

    # Get latest release
    Write-Host "==> Fetching latest release..."
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $headers = @{ "User-Agent" = "singbox2proxy-installer"; "Accept" = "application/vnd.github+json" }
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$REPO/releases/latest" -Headers $headers -TimeoutSec 15
        $tag = $release.tag_name
    } catch {
        Write-Host "==> Could not fetch release info. Falling back to Python mode..." -ForegroundColor Yellow
        Install-Python
        return
    }

    $assetName = "sb2p-windows-${arch}.exe"
    $downloadUrl = "https://github.com/$REPO/releases/download/$tag/$assetName"

    Write-Host "==> Downloading $assetName ($tag)..."
    $tmpFile = Join-Path $env:TEMP "sb2p-download.exe"

    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tmpFile -UseBasicParsing -TimeoutSec 60
    } catch {
        Write-Host "==> Binary not available for windows-$arch. Falling back to Python mode..." -ForegroundColor Yellow
        Install-Python
        return
    }

    if (-not (Test-Path $tmpFile) -or (Get-Item $tmpFile).Length -lt 1000) {
        Write-Host "==> Download failed. Falling back to Python mode..." -ForegroundColor Yellow
        Install-Python
        return
    }

    Ensure-InPath

    $dest = Join-Path $INSTALL_DIR "$BIN_NAME.exe"
    Move-Item -Path $tmpFile -Destination $dest -Force
    Create-Aliases -Source $dest

    Write-Host "==> Installed to $dest" -ForegroundColor Green
}

# ===========================================================
# PYTHON MODE
# ===========================================================
function Install-Python {
    # Detect Python
    $Python = $null
    foreach ($cmd in @("python", "python3", "py")) {
        try {
            $ver = & $cmd -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
            if ($ver) {
                $parts = $ver.Split(".")
                if ([int]$parts[0] -ge 3 -and [int]$parts[1] -ge 9) {
                    $Python = $cmd
                    break
                }
            }
        } catch {}
    }

    # Install Python if missing
    if (-not $Python) {
        Write-Host "==> Python 3.9+ not found, installing..." -ForegroundColor Yellow

        $installed = $false

        if (Get-Command winget -ErrorAction SilentlyContinue) {
            Write-Host "==> Installing Python via winget..."
            winget install Python.Python.3.12 --accept-package-agreements --accept-source-agreements --silent
            $installed = $true
        } elseif (Get-Command scoop -ErrorAction SilentlyContinue) {
            Write-Host "==> Installing Python via scoop..."
            scoop install python
            $installed = $true
        } elseif (Get-Command choco -ErrorAction SilentlyContinue) {
            Write-Host "==> Installing Python via choco..."
            choco install python3 -y
            $installed = $true
        }

        if (-not $installed) {
            Write-Host "==> Downloading Python from python.org..."
            $pyUrl = "https://www.python.org/ftp/python/3.12.4/python-3.12.4-amd64.exe"
            $pyInstaller = Join-Path $env:TEMP "python-installer.exe"

            try {
                Invoke-WebRequest -Uri $pyUrl -OutFile $pyInstaller -UseBasicParsing
                Write-Host "==> Installing Python (silent)..."
                Start-Process -FilePath $pyInstaller -ArgumentList "/quiet", "InstallAllUsers=0", "PrependPath=1", "Include_pip=1" -Wait -NoNewWindow
                Remove-Item $pyInstaller -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Host "ERROR: Could not install Python. Install manually from https://python.org" -ForegroundColor Red
                exit 1
            }
        }

        # Refresh PATH
        $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")

        foreach ($cmd in @("python", "python3", "py")) {
            try {
                $ver = & $cmd -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
                if ($ver) {
                    $parts = $ver.Split(".")
                    if ([int]$parts[0] -ge 3 -and [int]$parts[1] -ge 9) {
                        $Python = $cmd
                        break
                    }
                }
            } catch {}
        }

        if (-not $Python) {
            Write-Host "ERROR: Python not found after install. Restart terminal and try again." -ForegroundColor Red
            exit 1
        }
    }

    Write-Host "==> Using $Python ($(& $Python --version 2>&1))" -ForegroundColor Green

    # Install package
    & $Python -m pip install --upgrade pip 2>$null
    & $Python -m pip install singbox2proxy

    # Refresh PATH
    $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")

    # Ensure both aliases work — pip should create entry points, but verify
    Ensure-InPath

    if (-not (Get-Command $BIN_NAME -ErrorAction SilentlyContinue)) {
        # Create wrapper batch files
        $wrapperContent = "@echo off`r`n$Python -m singbox2proxy %*"
        Set-Content -Path (Join-Path $INSTALL_DIR "$BIN_NAME.cmd") -Value $wrapperContent -Force
        Set-Content -Path (Join-Path $INSTALL_DIR "$BIN_ALIAS.cmd") -Value $wrapperContent -Force
        Write-Host "==> Created wrapper scripts in $INSTALL_DIR" -ForegroundColor Green
    }
}

# ===========================================================
# Run
# ===========================================================
if ($Mode -eq "standalone") {
    Install-Standalone
} else {
    Install-Python
}

# --- Verify ---
$env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")

Write-Host ""
if (Get-Command $BIN_NAME -ErrorAction SilentlyContinue) {
    Write-Host "==> Done! singbox2proxy installed." -ForegroundColor Green
    Write-Host "    Usage:   sb2p `"vless://...`"" -ForegroundColor White
    Write-Host "             singbox2proxy `"vless://...`"" -ForegroundColor White
} else {
    Write-Host "==> Installation complete. Restart your terminal, then:" -ForegroundColor Yellow
    Write-Host "    sb2p `"vless://...`"" -ForegroundColor White
}
Write-Host ""
