<#
.SYNOPSIS
    Setup MININET-SDN Lab in WSL2 (Windows 10/11)
.DESCRIPTION
    Replica completa a VM-ului MININET-SDN (Ubuntu 24.04) in WSL2.
    Descarca kernel pre-compilat de pe GitHub Releases (~15MB, ~30 sec)
    in loc de compilare locala (~30 min).
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\setup-mininet-wsl2.ps1
    .\setup-mininet-wsl2.ps1 -SkipKernel
    .\setup-mininet-wsl2.ps1 -Phase3Only
    .\setup-mininet-wsl2.ps1 -LocalKernel "C:\path\to\kernel.tar.gz"
#>

[CmdletBinding()]
param(
    [switch]$SkipKernel,
    [switch]$Phase3Only,
    [string]$DistroName = "Ubuntu-24.04",
    [string]$WslUser = "stud",
    [string]$WslPass = "stud",
    [string]$GithubRepo = "antonioclim/wslaction",
    [string]$LocalKernel = ""
)

$ErrorActionPreference = "Stop"

# === UTILITIES ===

function Write-Banner {
    param([string]$Text, [string]$Color = "Cyan")
    Write-Host ""
    Write-Host ("=" * 65) -ForegroundColor $Color
    Write-Host "  $Text" -ForegroundColor $Color
    Write-Host ("=" * 65) -ForegroundColor $Color
}

function Write-Step {
    param([string]$Num, [string]$Text)
    Write-Host "  [$Num] " -ForegroundColor Yellow -NoNewline
    Write-Host $Text
}

function Write-Ok {
    param([string]$Text)
    Write-Host "  [OK] " -ForegroundColor Green -NoNewline
    Write-Host $Text
}

function Write-Warn {
    param([string]$Text)
    Write-Host "  [!!] " -ForegroundColor Yellow -NoNewline
    Write-Host $Text
}

function Write-Fail {
    param([string]$Text)
    Write-Host "  [FAIL] " -ForegroundColor Red -NoNewline
    Write-Host $Text
}

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-WslRoot {
    param([string]$Command)
    $result = wsl -d $script:DistroName -u root -- bash -c $Command 2>&1
    return $result
}

function Invoke-WslScript {
    param([string]$ScriptContent)
    $tag = [guid]::NewGuid().ToString("N").Substring(0,8)
    $tempFile = Join-Path $env:TEMP ("wsl-s-" + $tag + ".sh")
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($tempFile, $ScriptContent, $utf8NoBom)
    # Convert Windows path to WSL: C:\Users\... -> /mnt/c/Users/...
    $drive = $tempFile.Substring(0,1).ToLower()
    $rest = $tempFile.Substring(2) -replace '\\','/'
    $wslPath = "/mnt/" + $drive + $rest
    wsl -d $script:DistroName -u root -- bash $wslPath
    $ec = $LASTEXITCODE
    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
    return $ec
}

# === HEADER ===

Write-Host ""
Write-Host "+===============================================================+" -ForegroundColor Cyan
Write-Host "|     MININET-SDN  ->  WSL2  Migration Script                   |" -ForegroundColor Cyan
Write-Host "|     Pre-compiled kernel + full SDN stack (~10 min total)       |" -ForegroundColor Cyan
Write-Host "+===============================================================+" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Admin)) {
    Write-Fail "Scriptul necesita drepturi de Administrator!"
    Write-Host "  -> Click dreapta pe PowerShell -> Run as Administrator" -ForegroundColor Gray
    exit 1
}

$winVer = [System.Environment]::OSVersion.Version
$winBuild = $winVer.Build
Write-Host "  OS: Windows $($winVer.Major).$($winVer.Minor) Build $winBuild" -ForegroundColor Gray

if ($winBuild -lt 19041) {
    Write-Fail "WSL2 necesita Windows 10 Build 19041+."
    exit 1
}

$isWin11 = ($winBuild -ge 22000)
if ($isWin11) {
    Write-Ok "Windows 11 -- moduri mirrored/bridged disponibile"
}
else {
    Write-Warn "Windows 10 -- NAT only (broadcast/multicast limitat)"
}

if ($Phase3Only) {
    $SkipKernel = $true
}

# =========================================================================
# PHASE 0: ENABLE WSL2 + INSTALL UBUNTU 24.04
# =========================================================================
if (-not $Phase3Only) {
    Write-Banner "FAZA 0/3 - ACTIVARE WSL2 + UBUNTU 24.04"

    # 0a. WSL feature
    Write-Step "0a" "Activare Windows Subsystem for Linux..."
    $wslFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux
    if ($wslFeature.State -ne "Enabled") {
        Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart -WarningAction SilentlyContinue | Out-Null
        Write-Ok "WSL activat"
    }
    else {
        Write-Ok "WSL deja activat"
    }

    # 0b. VMP feature
    Write-Step "0b" "Activare Virtual Machine Platform..."
    $vmpFeature = Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform
    if ($vmpFeature.State -ne "Enabled") {
        Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart -WarningAction SilentlyContinue | Out-Null
        Write-Ok "VMP activat"
    }
    else {
        Write-Ok "VMP deja activat"
    }

    # 0c. Update WSL
    Write-Step "0c" "Actualizare WSL..."
    try {
        wsl --update 2>$null
        Write-Ok "WSL actualizat"
    }
    catch {
        Write-Warn "Nu s-a putut actualiza WSL"
    }

    # 0d. Set WSL2 default
    Write-Step "0d" "WSL2 ca versiune implicita..."
    wsl --set-default-version 2 2>$null
    Write-Ok "WSL2 implicit"

    # 0e. Install distro
    Write-Step "0e" "Verificare/Instalare $DistroName..."
    $rawList = wsl -l -q 2>$null
    $installedDistros = @()
    if ($rawList) {
        $installedDistros = $rawList | ForEach-Object { ($_ -replace '\x00','').Trim() } | Where-Object { $_ -match '\S' }
    }

    $distroFound = $false
    foreach ($d in $installedDistros) {
        if ($d -eq $DistroName -or $d -eq ($DistroName -replace '-','') -or $d -eq "Ubuntu") {
            $distroFound = $true
            break
        }
    }

    if (-not $distroFound) {
        Write-Host "    Instalare $DistroName..." -ForegroundColor Gray
        wsl --install -d $DistroName --no-launch 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Warn "Fallback: instalare ca Ubuntu..."
            wsl --install -d Ubuntu --no-launch 2>$null
            $DistroName = "Ubuntu"
        }
        Write-Ok "$DistroName instalat"
    }
    else {
        Write-Ok "$DistroName deja instalat"
    }

    # 0f. Create user
    Write-Step "0f" "Configurare utilizator $WslUser..."
    $userSetup = @'
#!/bin/bash
if ! id -u __USER__ 2>/dev/null; then
    useradd -m -s /bin/bash -G sudo __USER__
    echo '__USER__:__PASS__' | chpasswd
fi
echo '__USER__ ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/__USER__
chmod 440 /etc/sudoers.d/__USER__
'@
    $userSetup = $userSetup.Replace("__USER__", $WslUser)
    $userSetup = $userSetup.Replace("__PASS__", $WslPass)
    Invoke-WslScript -ScriptContent $userSetup | Out-Null
    Write-Ok "Utilizator $WslUser configurat"

    # 0g. wsl.conf
    Write-Step "0g" "Configurare /etc/wsl.conf..."
    $wslConfSetup = @'
#!/bin/bash
cat > /etc/wsl.conf << 'EOF'
[user]
default=stud

[boot]
systemd=true

[interop]
enabled=true
appendWindowsPath=true

[automount]
enabled=true
options="metadata,umask=22,fmask=11"
EOF
'@
    Invoke-WslScript -ScriptContent $wslConfSetup | Out-Null
    Write-Ok "/etc/wsl.conf (systemd=true)"
}

# =========================================================================
# PHASE 1: DOWNLOAD PRE-COMPILED KERNEL (instead of 30 min compilation)
# =========================================================================
$kernelDir = Join-Path $env:USERPROFILE ".wsl-kernels"
$kernelPath = Join-Path $kernelDir "bzImage"

if (-not $SkipKernel) {
    Write-Banner "FAZA 1/3 - DESCARCARE KERNEL PRE-COMPILAT"

    if (-not (Test-Path $kernelDir)) {
        New-Item -ItemType Directory -Path $kernelDir -Force | Out-Null
    }

    $archivePath = Join-Path $env:TEMP "wsl2-sdn-kernel.tar.gz"

    if ($LocalKernel -and (Test-Path $LocalKernel)) {
        # --- LOCAL ARCHIVE ---
        Write-Step "1a" "Folosire kernel local: $LocalKernel"
        Copy-Item $LocalKernel $archivePath -Force
        Write-Ok "Copiat din fisier local"
    }
    else {
        # --- DOWNLOAD FROM GITHUB RELEASES ---
        Write-Step "1a" "Interogare GitHub Releases: $GithubRepo..."

        $apiUrl = "https://api.github.com/repos/$GithubRepo/releases/latest"
        $downloadUrl = $null

        try {
            # PS 5.1 compatible: use basic parsing
            $headers = @{ "User-Agent" = "WSL2-SDN-Setup" }
            $releaseJson = Invoke-RestMethod -Uri $apiUrl -Headers $headers -ErrorAction Stop
            $asset = $releaseJson.assets | Where-Object { $_.name -match '\.tar\.gz$' } | Select-Object -First 1
            if ($asset) {
                $downloadUrl = $asset.browser_download_url
                $assetSize = [math]::Round($asset.size / 1MB, 1)
                Write-Ok "Gasit: $($asset.name) ($assetSize MB)"
            }
        }
        catch {
            Write-Warn "Nu s-a putut accesa GitHub API: $_"
        }

        if (-not $downloadUrl) {
            Write-Fail "Nu s-a gasit un release valid in $GithubRepo"
            Write-Host ""
            Write-Host "  Optiuni:" -ForegroundColor Yellow
            Write-Host "    1. Creaza un release in repo-ul tau GitHub:" -ForegroundColor Gray
            Write-Host "       git tag v1.0.0; git push origin v1.0.0" -ForegroundColor Gray
            Write-Host "       (GitHub Actions va compila automat)" -ForegroundColor Gray
            Write-Host ""
            Write-Host "    2. Compileaza manual si ruleaza cu -LocalKernel:" -ForegroundColor Gray
            Write-Host "       .\setup-mininet-wsl2.ps1 -LocalKernel C:\path\to\kernel.tar.gz" -ForegroundColor Gray
            Write-Host ""
            Write-Host "    3. Schimba repo-ul:" -ForegroundColor Gray
            Write-Host "       .\setup-mininet-wsl2.ps1 -GithubRepo user/repo" -ForegroundColor Gray
            exit 1
        }

        Write-Step "1b" "Descarcare kernel..."
        try {
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $downloadUrl -OutFile $archivePath -UseBasicParsing
            $ProgressPreference = 'Continue'
            $dlSize = [math]::Round((Get-Item $archivePath).Length / 1MB, 1)
            Write-Ok "Descarcat: $dlSize MB"
        }
        catch {
            Write-Fail "Descarcare esuata: $_"
            exit 1
        }
    }

    # --- EXTRACT KERNEL ---
    Write-Step "1c" "Extragere bzImage + module..."

    # Extract bzImage to Windows side
    $extractScript = @'
#!/bin/bash
set -e
ARCHIVE="__ARCHIVE_PATH__"
KERNEL_WIN="__KERNEL_DIR__"
STAGING="/tmp/wsl2-kernel-staging"

rm -rf "$STAGING"
mkdir -p "$STAGING"

echo "[INFO] Extracting archive..."
tar xzf "$ARCHIVE" -C "$STAGING"

# Find bzImage (might be at root or in a subfolder)
BZIMAGE=$(find "$STAGING" -name 'bzImage' -type f | head -1)
if [ -z "$BZIMAGE" ]; then
    echo "[FAIL] bzImage not found in archive!"
    exit 1
fi

# Find modules directory
MODULES_DIR=$(find "$STAGING" -type d -name 'modules' | head -1)

# Find kernel version
KVER_FILE=$(find "$STAGING" -name 'KERNEL_VERSION' -type f | head -1)
if [ -n "$KVER_FILE" ]; then
    KVER=$(cat "$KVER_FILE")
    echo "[INFO] Kernel version: $KVER"
else
    # Try to detect from modules path
    KVER=$(ls "$MODULES_DIR"/ 2>/dev/null | head -1)
    echo "[INFO] Kernel version (detected): $KVER"
fi

# Copy bzImage to Windows
mkdir -p "$KERNEL_WIN"
cp "$BZIMAGE" "$KERNEL_WIN/bzImage"
echo "[OK] bzImage -> $KERNEL_WIN/bzImage"

# Install modules into WSL2
if [ -n "$MODULES_DIR" ] && [ -d "$MODULES_DIR" ]; then
    echo "[INFO] Installing kernel modules..."
    cp -a "$MODULES_DIR"/* /lib/modules/ 2>/dev/null || true
    # Run depmod for each version installed
    for ver_dir in /lib/modules/*/; do
        ver=$(basename "$ver_dir")
        if [ -f "$ver_dir/modules.dep" ] || [ -d "$ver_dir/kernel" ]; then
            depmod "$ver" 2>/dev/null || true
        fi
    done
    echo "[OK] Modules installed in /lib/modules/"
else
    echo "[WARN] No modules directory found in archive"
fi

# Cleanup
rm -rf "$STAGING"
echo "[OK] Kernel extraction complete"
'@
    # Convert Windows paths to WSL paths for the script
    $archiveWsl = "/mnt/" + $archivePath.Substring(0,1).ToLower() + ($archivePath.Substring(2) -replace '\\','/')
    $kernelDirWsl = "/mnt/" + $kernelDir.Substring(0,1).ToLower() + ($kernelDir.Substring(2) -replace '\\','/')

    $extractScript = $extractScript.Replace("__ARCHIVE_PATH__", $archiveWsl)
    $extractScript = $extractScript.Replace("__KERNEL_DIR__", $kernelDirWsl)

    $exitCode = Invoke-WslScript -ScriptContent $extractScript
    if ($exitCode -ne 0) {
        Write-Fail "Extragere kernel esuata"
        exit 1
    }

    # Cleanup temp archive
    Remove-Item $archivePath -Force -ErrorAction SilentlyContinue

    if (-not (Test-Path $kernelPath)) {
        Write-Fail "bzImage nu a fost gasit la: $kernelPath"
        exit 1
    }
    $kSize = [math]::Round((Get-Item $kernelPath).Length / 1MB, 1)
    Write-Ok "Kernel instalat: $kernelPath ($kSize MB)"
}

# =========================================================================
# PHASE 2: CONFIGURE .wslconfig + RESTART WSL
# =========================================================================
if (-not $Phase3Only) {
    Write-Banner "FAZA 2/3 - CONFIGURARE .wslconfig + RESTART"

    $wslconfigPath = Join-Path $env:USERPROFILE ".wslconfig"
    $kernelWinPath = $kernelPath -replace '\\','\\\\'

    $totalRamGB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 0)
    $wslRamGB = [math]::Min(4, [math]::Floor($totalRamGB / 2))
    if ($wslRamGB -lt 2) {
        $wslRamGB = 2
    }

    Write-Step "2a" "Generare .wslconfig (RAM: ${wslRamGB}GB)..."

    $cfgLines = @(
        "[wsl2]"
        "kernel=$kernelWinPath"
        "memory=${wslRamGB}GB"
        "processors=2"
        "swap=2GB"
        "localhostForwarding=true"
        "nestedVirtualization=false"
    )

    if ($isWin11) {
        $cfgLines += ""
        $cfgLines += "[experimental]"
        $cfgLines += "networkingMode=mirrored"
        $cfgLines += "dnsTunneling=true"
        $cfgLines += "autoProxy=true"
        $cfgLines += "firewall=false"
        Write-Ok "Windows 11: mod mirrored activat"
    }
    else {
        $cfgLines += ""
        $cfgLines += "# Windows 10: doar NAT disponibil"
        Write-Warn "Windows 10: NAT only"
    }

    $cfgLines -join "`r`n" | Set-Content -Path $wslconfigPath -Encoding ASCII
    Write-Ok ".wslconfig salvat"

    # Restart WSL
    Write-Step "2b" "Restart WSL2..."
    wsl --shutdown
    Start-Sleep -Seconds 3
    $kernelVer = (wsl -d $DistroName -- uname -r 2>$null)
    Write-Ok "Kernel activ: $kernelVer"

    # Verify OVS module
    Write-Step "2c" "Verificare OVS module..."
    $ovsTestScript = @'
#!/bin/bash
modprobe openvswitch 2>/dev/null
if lsmod 2>/dev/null | grep -q openvswitch; then
    echo "OVS_OK"
else
    echo "OVS_FAIL"
fi
'@
    $ovsResult = Invoke-WslScript -ScriptContent $ovsTestScript
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "Module OVS verificate"
    }
    else {
        Write-Warn "Verificare OVS: rulati manual 'lsmod | grep openvswitch'"
    }

    # Configure boot auto-load
    Write-Step "2d" "Auto-load module la boot..."
    $bootConfScript = @'
#!/bin/bash
cat > /etc/wsl.conf << 'EOF'
[user]
default=stud

[boot]
systemd=true
command=modprobe -a openvswitch bridge sch_htb sch_netem sch_hfsc sch_tbf sch_red dummy 8021q 2>/dev/null; service openvswitch-switch start 2>/dev/null; true

[interop]
enabled=true
appendWindowsPath=true

[automount]
enabled=true
options="metadata,umask=22,fmask=11"
EOF
'@
    Invoke-WslScript -ScriptContent $bootConfScript | Out-Null
    Write-Ok "wsl.conf cu auto-load SDN modules"
}

# =========================================================================
# PHASE 3: INSTALL FULL STACK
# =========================================================================
Write-Banner "FAZA 3/3 - INSTALARE STACK COMPLET"

$p3 = @'
#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
TU="stud"
TH="/home/$TU"

echo ""
echo "---- 3.1 ACTUALIZARE SISTEM ----"
apt-get update -qq
apt-get upgrade -y -qq 2>&1 | tail -3
echo "[OK] Sistem actualizat"

echo ""
echo "---- 3.2 PACHETE APT ----"
echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections

PACKAGES=(
    mininet openvswitch-switch openvswitch-testcontroller
    net-tools dnsutils iputils-ping traceroute tcpdump tshark wireshark
    netcat-openbsd iperf3 iproute2 ethtool nmap nikto
    build-essential git curl wget unzip zip
    python3 python3-pip python3-venv python3-dev python-is-python3
    libffi-dev libssl-dev zlib1g-dev
    default-jre-headless graphviz xterm xauth
    mosquitto-clients nano vim-common tldr openssh-server
)

echo "[INFO] Instalare ${#PACKAGES[@]} pachete..."
apt-get install -y -qq "${PACKAGES[@]}" 2>&1 | tail -5
RC=$?
if [ "$RC" -ne 0 ]; then
    echo "[WARN] Retry individual..."
    for pkg in "${PACKAGES[@]}"; do
        apt-get install -y -qq "$pkg" 2>/dev/null || echo "[WARN] Skip: $pkg"
    done
fi
echo "[OK] Pachete APT"

echo ""
echo "---- 3.3 DOCKER ENGINE ----"
if ! command -v docker >/dev/null 2>&1; then
    echo "[INFO] Instalare Docker Engine..."
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    ARCH=$(dpkg --print-architecture)
    CODENAME=$(. /etc/os-release; echo "$VERSION_CODENAME")
    echo "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${CODENAME} stable" > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin 2>&1 | tail -3
    echo "[OK] Docker Engine instalat"
else
    echo "[OK] Docker deja instalat"
fi

# Fix iptables (WSL2 nftables incompatibility)
update-alternatives --set iptables /usr/sbin/iptables-legacy 2>/dev/null || true
update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy 2>/dev/null || true

systemctl enable docker 2>/dev/null || true
systemctl start docker 2>/dev/null || service docker start 2>/dev/null || true
usermod -aG docker "$TU" 2>/dev/null || true

echo "[INFO] Pull imagini Docker..."
docker pull nginx:alpine 2>/dev/null || echo "[WARN] nginx:alpine skip"
docker pull traefik/whoami:latest 2>/dev/null || echo "[WARN] traefik/whoami skip"

echo ""
echo "---- 3.4 PYTHON VENV compnet ----"
VENV="$TH/venvs/compnet"
sudo -u "$TU" mkdir -p "$TH/venvs"
sudo -u "$TU" python3 -m venv "$VENV"

echo "[INFO] Instalare biblioteci Python..."
sudo -u "$TU" bash -c "
    source '$VENV/bin/activate'
    pip install --upgrade pip setuptools wheel 2>&1 | tail -1
    pip install \
        requests Flask flask-sock \
        dnspython dnslib pyftpdlib \
        paramiko paho-mqtt scapy \
        grpcio grpcio-tools os-ken \
        aiosmtpd ncclient netaddr ovs \
        lxml PyYAML eventlet invoke oslo.config \
        2>&1 | tail -5
"
echo "[OK] Python venv compnet"

echo ""
echo "---- 3.5 GRUPURI ----"
for grp in sudo docker wireshark; do
    if getent group "$grp" >/dev/null 2>&1; then
        usermod -aG "$grp" "$TU" 2>/dev/null
        echo "[OK] $TU -> $grp"
    fi
done
if [ -f /usr/bin/dumpcap ]; then
    setcap 'cap_net_raw,cap_net_admin=eip' /usr/bin/dumpcap 2>/dev/null || true
    echo "[OK] Wireshark captura fara sudo"
fi

echo ""
echo "---- 3.6 BASHRC ----"
BASHRC="$TH/.bashrc"
if ! grep -q "MININET-SDN-WSL2" "$BASHRC" 2>/dev/null; then
    cat >> "$BASHRC" << 'RCBLOCK'

# ==============================================================
# MININET-SDN-WSL2 -- Configurare identica cu VM-ul
# ==============================================================
export EDITOR=nano
export VISUAL=nano
alias vi='nano'
alias vim='nano'
alias man='tldr'
alias ll='ls -alF --color=auto'
alias la='ls -A --color=auto'
alias l='ls -CF --color=auto'
alias grep='grep --color=auto'
alias mn-test='sudo mn --test pingall'
alias mn-clean='sudo mn -c'
alias ovs-show='sudo ovs-vsctl show'
alias dps='docker ps -a --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"'
alias dcu='docker compose up -d'
alias dcd='docker compose down'

if ! lsmod 2>/dev/null | grep -q openvswitch; then
    sudo modprobe -a openvswitch 2>/dev/null || true
fi

if [ -d "$HOME/venvs/compnet" ] && [ -f "$HOME/venvs/compnet/bin/activate" ]; then
    source "$HOME/venvs/compnet/bin/activate"
fi
# ==============================================================
RCBLOCK
    echo "[OK] .bashrc configurat"
else
    echo "[OK] .bashrc deja configurat"
fi
update-alternatives --set editor /bin/nano 2>/dev/null || true

echo ""
echo "---- 3.7 BANNERE ----"
cat > /etc/issue << 'ISSUEFILE'

==========================================================
       WELCOME to NETWORKING SEMINARS! (WSL2 Edition)
==========================================================

ISSUEFILE

cat > /etc/update-motd.d/01-custom-welcome << 'MOTDFILE'
#!/bin/sh
echo ""
echo "=========================================================="
echo "       SUCCESS! YOU ARE INSIDE MININET-SDN (WSL2)         "
echo "=========================================================="
echo ""
echo "QUICK TIPS:"
echo " -> tldr <command> for examples (better than man)."
echo " -> nano is default editor (vi/vim aliased)."
echo " -> os-ken, grpc, scapy pre-installed in venv."
echo " -> Docker: no sudo needed."
echo ""
echo "WSL2 NOTES:"
echo " -> OVS modules: auto-loaded at boot"
echo " -> GUI apps: xterm, wireshark via WSLg"
echo " -> Shared: /mnt/c/ = C: drive"
echo ""
MOTDFILE
chmod +x /etc/update-motd.d/01-custom-welcome
chmod -x /etc/update-motd.d/10-help-text 2>/dev/null || true
chmod -x /etc/update-motd.d/50-motd-news 2>/dev/null || true
chmod -x /etc/update-motd.d/60-unminimize 2>/dev/null || true
echo "[OK] MOTD"

echo ""
echo "---- 3.8 SSH ----"
cat > /etc/ssh/sshd_config.d/mininet-sdn.conf << 'SSHDCONF'
AddressFamily inet
X11Forwarding yes
X11UseLocalhost no
PasswordAuthentication yes
KbdInteractiveAuthentication no
PrintMotd no
SSHDCONF
systemctl enable ssh 2>/dev/null || true
systemctl restart ssh 2>/dev/null || service ssh restart 2>/dev/null || true
echo "[OK] SSH (X11Forwarding=yes)"

echo ""
echo "---- 3.9 OVS + MININET ----"
modprobe -a openvswitch 2>/dev/null || echo "[WARN] openvswitch not loaded"
modprobe -a sch_htb sch_netem sch_hfsc sch_tbf sch_red 2>/dev/null || true
service openvswitch-switch start 2>/dev/null || true
if command -v mn >/dev/null 2>&1; then
    echo "[OK] Mininet: $(mn --version 2>/dev/null)"
fi
if command -v ovs-vsctl >/dev/null 2>&1; then
    echo "[OK] OVS: $(ovs-vsctl --version 2>/dev/null | head -1)"
fi

echo ""
echo "---- 3.10 TLDR ----"
sudo -u "$TU" tldr --update 2>/dev/null || true
echo "[OK] TLDR"

echo ""
echo "---- 3.11 PERMISIUNI ----"
chown -R "$TU:$TU" "$TH"
echo "$TU ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/$TU"
chmod 440 "/etc/sudoers.d/$TU"
echo "[OK] Sudo NOPASSWD"

echo ""
echo "==== SELF-TEST ===="
echo "  Kernel:    $(uname -r)"
OVSMOD=0
if lsmod 2>/dev/null | grep -q openvswitch; then OVSMOD=1; fi
if [ "$OVSMOD" -eq 1 ]; then echo "  OVS:       LOADED"; else echo "  OVS:       NOT LOADED (reboot to load)"; fi
echo "  Mininet:   $(mn --version 2>/dev/null || echo 'check')"
echo "  Docker:    $(docker --version 2>/dev/null || echo 'check')"
echo "  Venv:      $VENV"
SSHSTATE="unknown"
if systemctl is-active ssh >/dev/null 2>&1; then SSHSTATE="active"; fi
echo "  SSH:       $SSHSTATE"
echo "  tshark:    $(tshark --version 2>/dev/null | head -1 || echo 'check')"
echo ""
echo "========================================="
echo "  INSTALARE COMPLETA!"
echo "========================================="
'@

Write-Step "3" "Lansare instalare stack..."
$exitCode = Invoke-WslScript -ScriptContent $p3
if ($exitCode -ne 0) {
    Write-Warn "Instalarea a intampinat erori (exit code: $exitCode)"
}

# =========================================================================
# FINAL: PORT FORWARDING + SUMMARY
# =========================================================================
Write-Banner "CONFIGURARE FINALA" "Green"

# Port forwarding SSH
Write-Step "F1" "Port forwarding SSH (2222 -> WSL:22)..."
$wslIP = $null
try {
    $rawIP = wsl -d $DistroName -- hostname -I 2>$null
    if ($rawIP) {
        $wslIP = $rawIP.Trim().Split(' ')[0]
    }
}
catch { }

if ($wslIP) {
    netsh interface portproxy delete v4tov4 listenport=2222 listenaddress=127.0.0.1 2>$null | Out-Null
    netsh interface portproxy add v4tov4 listenport=2222 listenaddress=127.0.0.1 connectport=22 connectaddress=$wslIP 2>$null
    Write-Ok "127.0.0.1:2222 -> ${wslIP}:22"
}
else {
    Write-Warn "Nu s-a detectat IP-ul WSL2"
}

# Firewall
Write-Step "F2" "Regula firewall..."
New-NetFirewallRule -DisplayName "WSL2 SSH (2222)" -Direction Inbound -LocalPort 2222 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue | Out-Null
Write-Ok "Firewall OK"

# Re-forward helper script
$rfPath = Join-Path $env:USERPROFILE "re-forward-ssh.ps1"
$rfLines = @(
    '# re-forward-ssh.ps1 -- Run after each WSL restart'
    ('$ip = (wsl -d ' + $DistroName + ' -- hostname -I).Trim().Split('' '')[0]')
    'netsh interface portproxy delete v4tov4 listenport=2222 listenaddress=127.0.0.1 2>$null'
    'netsh interface portproxy add v4tov4 listenport=2222 listenaddress=127.0.0.1 connectport=22 connectaddress=$ip'
    'Write-Host "SSH: 127.0.0.1:2222 -> $($ip):22" -ForegroundColor Green'
)
$rfLines -join "`r`n" | Set-Content -Path $rfPath -Encoding ASCII
Write-Ok "Helper: $rfPath"

# === SUMMARY ===
Write-Host ""
Write-Host "+===============================================================+" -ForegroundColor Green
Write-Host "|   MININET-SDN WSL2 -- SETUP COMPLET!                         |" -ForegroundColor Green
Write-Host "+---------------------------------------------------------------+" -ForegroundColor Green
Write-Host "|                                                               |" -ForegroundColor Green
Write-Host "|  Conectare:                                                   |" -ForegroundColor Green
Write-Host "|    ssh -p 2222 stud@127.0.0.1                                |" -ForegroundColor Green
Write-Host "|    wsl -d $DistroName                                         |" -ForegroundColor Green
Write-Host "|                                                               |" -ForegroundColor Green
Write-Host "|  Teste:                                                       |" -ForegroundColor Green
Write-Host "|    sudo mn --test pingall                                     |" -ForegroundColor Green
Write-Host "|    docker run --rm hello-world                                |" -ForegroundColor Green
Write-Host "|    python -c 'import scapy; print(scapy.VERSION)'            |" -ForegroundColor Green
Write-Host "|                                                               |" -ForegroundColor Green
if (-not $isWin11) {
    Write-Host "|  !! Win10: broadcast/multicast extern NU functioneaza        |" -ForegroundColor Yellow
    Write-Host "|     Mininet intern OK. Upgrade Win11 -> mirrored/bridged.    |" -ForegroundColor Yellow
    Write-Host "|                                                               |" -ForegroundColor Green
}
Write-Host "|  Dupa restart WSL: .\re-forward-ssh.ps1 (Admin PS)           |" -ForegroundColor Green
Write-Host "+===============================================================+" -ForegroundColor Green
Write-Host ""
