#!/usr/bin/env bash
###############################################################################
#  extract-vm-blueprint.sh
#  ──────────────────────────────────────────────────────────────────────────
#  Script de extracție completă a configurării VM MININET-SDN (Ubuntu 24.04)
#  Autor:  ing. dr. Antonio Clim – ASE-CSIE
#  Scop:   Capturează ABSOLUT TOT ceea ce s-a instalat și configurat,
#           generând o arhivă autonomă pentru reproducerea identică a VM-ului.
#
#  Utilizare:
#      chmod +x extract-vm-blueprint.sh
#      ./extract-vm-blueprint.sh            # cu user stud (cere sudo)
#      sudo ./extract-vm-blueprint.sh       # direct cu root
#
#  Output: ~/vm-blueprint-YYYY-MM-DD_HHMMSS.tar.gz
###############################################################################

set -euo pipefail
IFS=$'\n\t'

# ── Culori și utilități de afișare ──────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'
CYN='\033[0;36m'; BLD='\033[1m'; RST='\033[0m'

info()  { printf "${CYN}[INFO]${RST}  %s\n" "$*"; }
ok()    { printf "${GRN}[  OK]${RST}  %s\n" "$*"; }
warn()  { printf "${YLW}[WARN]${RST}  %s\n" "$*"; }
fail()  { printf "${RED}[FAIL]${RST}  %s\n" "$*"; }
header(){ printf "\n${BLD}${CYN}══════════════════════════════════════════${RST}\n"
          printf "${BLD}${CYN}  %s${RST}\n" "$*"
          printf "${BLD}${CYN}══════════════════════════════════════════${RST}\n"; }

# ── Verificări preliminare ──────────────────────────────────────────────────
TIMESTAMP=$(date +%Y-%m-%d_%H%M%S)
BLUEPRINT_DIR="/tmp/vm-blueprint-${TIMESTAMP}"
ARCHIVE_NAME="vm-blueprint-${TIMESTAMP}.tar.gz"
ARCHIVE_PATH="${HOME}/${ARCHIVE_NAME}"
TARGET_USER="${SUDO_USER:-stud}"
TARGET_HOME=$(eval echo "~${TARGET_USER}")

# Funcție pentru sudo transparent
run_sudo() {
    if [[ $EUID -eq 0 ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

mkdir -p "${BLUEPRINT_DIR}"/{system,packages,services,configs,network,docker,python,user,security,hardware,scripts}

header "EXTRACȚIE COMPLETĂ VM MININET-SDN"
info "Timestamp:    ${TIMESTAMP}"
info "Blueprint:    ${BLUEPRINT_DIR}"
info "User țintă:  ${TARGET_USER}"
info "Home dir:     ${TARGET_HOME}"

###############################################################################
# 1. INFORMAȚII SISTEM (HARDWARE + KERNEL + OS)
###############################################################################
header "1/12 · INFORMAȚII SISTEM"

{
    echo "=== OS Release ==="
    cat /etc/os-release 2>/dev/null
    echo -e "\n=== Kernel ==="
    uname -a
    echo -e "\n=== Uptime ==="
    uptime
    echo -e "\n=== CPU ==="
    lscpu 2>/dev/null || cat /proc/cpuinfo
    echo -e "\n=== Memorie ==="
    free -h
    echo -e "\n=== Discuri ==="
    lsblk 2>/dev/null
    df -Th 2>/dev/null
    echo -e "\n=== Timezone ==="
    timedatectl 2>/dev/null || cat /etc/timezone
    echo -e "\n=== Locale ==="
    locale
    echo -e "\n=== Hostname ==="
    hostnamectl 2>/dev/null || hostname
    echo -e "\n=== Kernel Modules Loaded ==="
    lsmod 2>/dev/null
    echo -e "\n=== Boot Parameters ==="
    cat /proc/cmdline 2>/dev/null
} > "${BLUEPRINT_DIR}/system/system-info.txt" 2>&1
ok "Informații sistem capturate"

# Fstab și mount points
run_sudo cp /etc/fstab "${BLUEPRINT_DIR}/system/fstab" 2>/dev/null || true
mount > "${BLUEPRINT_DIR}/system/mount-points.txt" 2>/dev/null
ok "Mount points și fstab"

###############################################################################
# 2. PACHETE INSTALATE (APT / DPKG / SNAP / PIP GLOBAL)
###############################################################################
header "2/12 · PACHETE INSTALATE"

# 2a. Toate pachetele dpkg (lista completă cu versiuni)
dpkg -l > "${BLUEPRINT_DIR}/packages/dpkg-full-list.txt" 2>/dev/null
ok "Lista completă dpkg ($(dpkg -l 2>/dev/null | grep '^ii' | wc -l) pachete)"

# 2b. Doar pachetele instalate manual (nu dependințe automate)
run_sudo apt-mark showmanual | sort > "${BLUEPRINT_DIR}/packages/apt-manual-packages.txt" 2>/dev/null
ok "Pachete instalate manual (apt-mark showmanual)"

# 2c. Surse APT (repositories)
{
    echo "=== /etc/apt/sources.list ==="
    cat /etc/apt/sources.list 2>/dev/null || echo "(nu există sau e gol)"
    echo -e "\n=== /etc/apt/sources.list.d/ ==="
    for f in /etc/apt/sources.list.d/*; do
        [ -f "$f" ] && echo "--- $f ---" && cat "$f"
    done
} > "${BLUEPRINT_DIR}/packages/apt-sources.txt" 2>&1

# 2d. Chei GPG pentru repo-uri
mkdir -p "${BLUEPRINT_DIR}/packages/apt-keyrings"
if [ -d /etc/apt/keyrings ]; then
    run_sudo cp -r /etc/apt/keyrings/* "${BLUEPRINT_DIR}/packages/apt-keyrings/" 2>/dev/null || true
fi
if [ -d /usr/share/keyrings ]; then
    # Doar keyrings non-standard (adăugate manual)
    shopt -s nullglob
    for f in /usr/share/keyrings/docker*.gpg /usr/share/keyrings/docker*.asc \
             /usr/share/keyrings/*nodesource* /usr/share/keyrings/*yarn*; do
        [ -f "$f" ] && run_sudo cp "$f" "${BLUEPRINT_DIR}/packages/apt-keyrings/" 2>/dev/null
    done
    shopt -u nullglob
fi
# Trusted GPG keys
run_sudo apt-key list > "${BLUEPRINT_DIR}/packages/apt-key-list.txt" 2>/dev/null || true
ok "Surse APT și chei GPG"

# 2e. Snap packages (dacă există)
if command -v snap &>/dev/null; then
    snap list > "${BLUEPRINT_DIR}/packages/snap-list.txt" 2>/dev/null
    ok "Snap packages"
fi

# 2f. Pachete pip globale (system-wide)
if command -v pip3 &>/dev/null; then
    pip3 list --format=freeze 2>/dev/null > "${BLUEPRINT_DIR}/packages/pip3-global.txt" || true
fi

# 2g. Software instalat manual (din /usr/local, /opt)
{
    echo "=== /usr/local/bin ==="
    ls -la /usr/local/bin/ 2>/dev/null
    echo -e "\n=== /usr/local/sbin ==="
    ls -la /usr/local/sbin/ 2>/dev/null
    echo -e "\n=== /opt ==="
    ls -la /opt/ 2>/dev/null
    echo -e "\n=== Binare non-dpkg în /usr/local/bin ==="
    for f in /usr/local/bin/*; do
        [ -f "$f" ] && ! dpkg -S "$f" &>/dev/null && echo "$f (manual install)"
    done
} > "${BLUEPRINT_DIR}/packages/manual-installs.txt" 2>&1
ok "Software instalat manual (/usr/local, /opt)"

###############################################################################
# 3. SERVICII SYSTEMD
###############################################################################
header "3/12 · SERVICII SYSTEMD"

# 3a. Toate unit-urile active
systemctl list-units --type=service --all --no-pager > "${BLUEPRINT_DIR}/services/systemd-all-services.txt" 2>/dev/null

# 3b. Servicii activate la boot
systemctl list-unit-files --type=service --no-pager > "${BLUEPRINT_DIR}/services/systemd-enabled.txt" 2>/dev/null

# 3c. Timere (cron-like)
systemctl list-timers --all --no-pager > "${BLUEPRINT_DIR}/services/systemd-timers.txt" 2>/dev/null

# 3d. Unit files custom
mkdir -p "${BLUEPRINT_DIR}/services/custom-units"
for unit_dir in /etc/systemd/system /etc/systemd/user; do
    if [ -d "$unit_dir" ]; then
        find "$unit_dir" -maxdepth 2 -name '*.service' -o -name '*.timer' -o -name '*.socket' 2>/dev/null | while read -r f; do
            relpath="${f#/etc/systemd/}"
            mkdir -p "${BLUEPRINT_DIR}/services/custom-units/$(dirname "$relpath")"
            run_sudo cp "$f" "${BLUEPRINT_DIR}/services/custom-units/$relpath" 2>/dev/null
        done
    fi
done

# 3e. Override-uri systemd
find /etc/systemd/system -name '*.d' -type d 2>/dev/null | while read -r d; do
    relpath="${d#/etc/systemd/system/}"
    mkdir -p "${BLUEPRINT_DIR}/services/custom-units/${relpath}"
    run_sudo cp -r "$d"/* "${BLUEPRINT_DIR}/services/custom-units/${relpath}/" 2>/dev/null || true
done
ok "Servicii systemd capturate"

###############################################################################
# 4. CONFIGURAȚIE REȚEA
###############################################################################
header "4/12 · CONFIGURAȚIE REȚEA"

{
    echo "=== Interfețe (ip addr) ==="
    ip addr show 2>/dev/null
    echo -e "\n=== Rute (ip route) ==="
    ip route show 2>/dev/null
    echo -e "\n=== DNS Rezolvare ==="
    cat /etc/resolv.conf 2>/dev/null
    resolvectl status 2>/dev/null || true
    echo -e "\n=== Hosts ==="
    cat /etc/hosts 2>/dev/null
    echo -e "\n=== Porturi deschise ==="
    ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null
    echo -e "\n=== iptables ==="
    run_sudo iptables -L -n -v 2>/dev/null || true
    echo -e "\n=== ip6tables ==="
    run_sudo ip6tables -L -n -v 2>/dev/null || true
    echo -e "\n=== UFW Status ==="
    run_sudo ufw status verbose 2>/dev/null || true
} > "${BLUEPRINT_DIR}/network/network-info.txt" 2>&1

# Netplan / interfaces config
mkdir -p "${BLUEPRINT_DIR}/network/netplan"
[ -d /etc/netplan ] && run_sudo cp /etc/netplan/*.yaml "${BLUEPRINT_DIR}/network/netplan/" 2>/dev/null || true
[ -f /etc/network/interfaces ] && run_sudo cp /etc/network/interfaces "${BLUEPRINT_DIR}/network/" 2>/dev/null || true

# NetworkManager (dacă există)
[ -d /etc/NetworkManager ] && run_sudo cp -r /etc/NetworkManager/system-connections "${BLUEPRINT_DIR}/network/nm-connections" 2>/dev/null || true

ok "Configurație rețea capturată"

###############################################################################
# 5. DOCKER (ENGINE + COMPOSE + IMAGES + CONFIGURARE)
###############################################################################
header "5/12 · DOCKER"

if command -v docker &>/dev/null; then
    {
        echo "=== Docker Version ==="
        docker version 2>/dev/null
        echo -e "\n=== Docker Info ==="
        docker info 2>/dev/null
        echo -e "\n=== Docker Images ==="
        docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.ID}}" 2>/dev/null
        echo -e "\n=== Docker Volumes ==="
        docker volume ls 2>/dev/null
        echo -e "\n=== Docker Networks ==="
        docker network ls 2>/dev/null
        docker network inspect $(docker network ls -q) 2>/dev/null || true
        echo -e "\n=== Docker Containers (all) ==="
        docker ps -a --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null
    } > "${BLUEPRINT_DIR}/docker/docker-info.txt" 2>&1

    # Docker daemon config
    [ -f /etc/docker/daemon.json ] && run_sudo cp /etc/docker/daemon.json "${BLUEPRINT_DIR}/docker/" 2>/dev/null
    
    # Docker compose files din home
    find "${TARGET_HOME}" -maxdepth 4 -name 'docker-compose*.yml' -o -name 'docker-compose*.yaml' -o -name 'Dockerfile' 2>/dev/null | while read -r f; do
        relpath="${f#${TARGET_HOME}/}"
        mkdir -p "${BLUEPRINT_DIR}/docker/compose-files/$(dirname "$relpath")"
        cp "$f" "${BLUEPRINT_DIR}/docker/compose-files/$relpath" 2>/dev/null
    done

    # Docker group membership
    getent group docker > "${BLUEPRINT_DIR}/docker/docker-group.txt" 2>/dev/null
    
    # Lista imagini pentru pull ulterior
    docker images --format "{{.Repository}}:{{.Tag}}" 2>/dev/null | grep -v '<none>' > "${BLUEPRINT_DIR}/docker/docker-images-pull-list.txt" 2>/dev/null
    
    ok "Docker capturată ($(docker images -q 2>/dev/null | wc -l) imagini)"
else
    warn "Docker nu este instalat"
fi

###############################################################################
# 6. PYTHON (VENV + BIBLIOTECI + CONFIGURARE)
###############################################################################
header "6/12 · PYTHON & VENV"

{
    echo "=== Python System ==="
    python3 --version 2>/dev/null
    which python3 2>/dev/null
    echo -e "\n=== Pip System ==="
    pip3 --version 2>/dev/null || true
} > "${BLUEPRINT_DIR}/python/python-system.txt" 2>&1

# Capturare TOATE venv-urile din home
find "${TARGET_HOME}" -maxdepth 4 -path "*/bin/activate" -type f 2>/dev/null | while read -r activate; do
    venv_dir=$(dirname "$(dirname "$activate")")
    venv_name=$(basename "$venv_dir")
    venv_relpath="${venv_dir#${TARGET_HOME}/}"
    
    info "  Venv detectat: ${venv_relpath}"
    mkdir -p "${BLUEPRINT_DIR}/python/venvs/${venv_name}"
    
    # Freeze requirements
    (source "$activate" && pip freeze) > "${BLUEPRINT_DIR}/python/venvs/${venv_name}/requirements.txt" 2>/dev/null || true
    
    # Pip list cu versiuni
    (source "$activate" && pip list --format=columns) > "${BLUEPRINT_DIR}/python/venvs/${venv_name}/pip-list.txt" 2>/dev/null || true
    
    # Python version din venv
    (source "$activate" && python --version) > "${BLUEPRINT_DIR}/python/venvs/${venv_name}/python-version.txt" 2>/dev/null || true
    
    # pyvenv.cfg
    [ -f "${venv_dir}/pyvenv.cfg" ] && cp "${venv_dir}/pyvenv.cfg" "${BLUEPRINT_DIR}/python/venvs/${venv_name}/" 2>/dev/null
done
ok "Python venv-uri capturate"

###############################################################################
# 7. CONFIGURĂRI UTILIZATOR (dotfiles, aliases, profile)
###############################################################################
header "7/12 · CONFIGURĂRI UTILIZATOR"

mkdir -p "${BLUEPRINT_DIR}/user/dotfiles"
mkdir -p "${BLUEPRINT_DIR}/user/root-dotfiles"

# Dotfiles pentru utilizatorul țintă
for dotfile in .bashrc .bash_aliases .bash_profile .profile .bash_logout \
               .nanorc .vimrc .gitconfig .tmux.conf .screenrc .inputrc \
               .selected_editor .hushlogin .Xresources .xprofile; do
    [ -f "${TARGET_HOME}/${dotfile}" ] && cp "${TARGET_HOME}/${dotfile}" "${BLUEPRINT_DIR}/user/dotfiles/" 2>/dev/null
done

# Directoare de configurare importante
for confdir in .ssh .config .local/bin; do
    if [ -d "${TARGET_HOME}/${confdir}" ]; then
        mkdir -p "${BLUEPRINT_DIR}/user/dotfiles/${confdir}"
        # SSH: doar config, authorized_keys, known_hosts (NU cheile private!)
        if [ "$confdir" = ".ssh" ]; then
            for sf in config authorized_keys known_hosts; do
                [ -f "${TARGET_HOME}/.ssh/${sf}" ] && cp "${TARGET_HOME}/.ssh/${sf}" "${BLUEPRINT_DIR}/user/dotfiles/.ssh/" 2>/dev/null
            done
            # Salvare permisiuni .ssh
            ls -la "${TARGET_HOME}/.ssh/" > "${BLUEPRINT_DIR}/user/dotfiles/.ssh/permissions.txt" 2>/dev/null
        else
            cp -r "${TARGET_HOME}/${confdir}"/* "${BLUEPRINT_DIR}/user/dotfiles/${confdir}/" 2>/dev/null || true
        fi
    fi
done

# Root dotfiles (dacă au fost modificate)
for dotfile in .bashrc .bash_aliases .profile; do
    [ -f "/root/${dotfile}" ] && run_sudo cp "/root/${dotfile}" "${BLUEPRINT_DIR}/user/root-dotfiles/" 2>/dev/null
done

# Crontabs
crontab -u "${TARGET_USER}" -l > "${BLUEPRINT_DIR}/user/crontab-${TARGET_USER}.txt" 2>/dev/null || true
run_sudo crontab -l > "${BLUEPRINT_DIR}/user/crontab-root.txt" 2>/dev/null || true
[ -d /etc/cron.d ] && run_sudo cp -r /etc/cron.d "${BLUEPRINT_DIR}/user/cron.d" 2>/dev/null || true

ok "Dotfiles și configurări utilizator"

###############################################################################
# 8. SECURITATE (GRUPURI, SUDOERS, SSH, PAM)
###############################################################################
header "8/12 · SECURITATE & UTILIZATORI"

{
    echo "=== Utilizatori cu shell valid ==="
    grep -v '/nologin\|/false' /etc/passwd
    echo -e "\n=== Toate grupurile ==="
    cat /etc/group
    echo -e "\n=== Grupuri utilizator ${TARGET_USER} ==="
    id "${TARGET_USER}" 2>/dev/null
    groups "${TARGET_USER}" 2>/dev/null
    echo -e "\n=== Sudoers ==="
    run_sudo cat /etc/sudoers 2>/dev/null
} > "${BLUEPRINT_DIR}/security/users-groups.txt" 2>&1

# Sudoers.d
mkdir -p "${BLUEPRINT_DIR}/security/sudoers.d"
if [ -d /etc/sudoers.d ]; then
    run_sudo find /etc/sudoers.d -type f 2>/dev/null | while read -r f; do
        run_sudo cp "$f" "${BLUEPRINT_DIR}/security/sudoers.d/" 2>/dev/null
    done
fi

# SSH daemon config
run_sudo cp /etc/ssh/sshd_config "${BLUEPRINT_DIR}/security/" 2>/dev/null || true
[ -d /etc/ssh/sshd_config.d ] && run_sudo cp -r /etc/ssh/sshd_config.d "${BLUEPRINT_DIR}/security/" 2>/dev/null || true

# PAM configs relevante
mkdir -p "${BLUEPRINT_DIR}/security/pam.d"
for pam in common-auth common-password sshd sudo; do
    [ -f "/etc/pam.d/${pam}" ] && run_sudo cp "/etc/pam.d/${pam}" "${BLUEPRINT_DIR}/security/pam.d/" 2>/dev/null
done

ok "Securitate și utilizatori"

###############################################################################
# 9. BANNERE, MOTD, ISSUE
###############################################################################
header "9/12 · BANNERE & MOTD"

# Pre-login banner
[ -f /etc/issue ] && run_sudo cp /etc/issue "${BLUEPRINT_DIR}/configs/" 2>/dev/null
[ -f /etc/issue.net ] && run_sudo cp /etc/issue.net "${BLUEPRINT_DIR}/configs/" 2>/dev/null

# MOTD complet
mkdir -p "${BLUEPRINT_DIR}/configs/update-motd.d"
if [ -d /etc/update-motd.d ]; then
    run_sudo cp -r /etc/update-motd.d/* "${BLUEPRINT_DIR}/configs/update-motd.d/" 2>/dev/null || true
fi
[ -f /etc/motd ] && run_sudo cp /etc/motd "${BLUEPRINT_DIR}/configs/" 2>/dev/null || true

ok "Bannere și MOTD"

###############################################################################
# 10. CONFIGURĂRI SISTEM DIVERSE
###############################################################################
header "10/12 · CONFIGURĂRI SISTEM"

# Sysctl
run_sudo sysctl -a > "${BLUEPRINT_DIR}/configs/sysctl-runtime.txt" 2>/dev/null || true
[ -f /etc/sysctl.conf ] && run_sudo cp /etc/sysctl.conf "${BLUEPRINT_DIR}/configs/" 2>/dev/null
[ -d /etc/sysctl.d ] && run_sudo cp -r /etc/sysctl.d "${BLUEPRINT_DIR}/configs/sysctl.d" 2>/dev/null || true

# Environment
[ -f /etc/environment ] && run_sudo cp /etc/environment "${BLUEPRINT_DIR}/configs/" 2>/dev/null
[ -f /etc/default/locale ] && run_sudo cp /etc/default/locale "${BLUEPRINT_DIR}/configs/" 2>/dev/null

# Login.defs
[ -f /etc/login.defs ] && run_sudo cp /etc/login.defs "${BLUEPRINT_DIR}/configs/" 2>/dev/null

# Alternatives (editor, python, etc.)
update-alternatives --get-selections > "${BLUEPRINT_DIR}/configs/alternatives.txt" 2>/dev/null || true

# GRUB
[ -f /etc/default/grub ] && run_sudo cp /etc/default/grub "${BLUEPRINT_DIR}/configs/" 2>/dev/null

# Wireshark group config (captură fără sudo)
if [ -f /etc/wireshark/init.lua ] || dpkg -s wireshark-common &>/dev/null; then
    {
        echo "=== Wireshark Dumpcap Capabilities ==="
        getcap /usr/bin/dumpcap 2>/dev/null || true
        echo "=== Wireshark Group ==="
        getent group wireshark 2>/dev/null || true
    } > "${BLUEPRINT_DIR}/configs/wireshark-config.txt" 2>&1
fi

# Mininet-related configs
[ -d /etc/openvswitch ] && run_sudo cp -r /etc/openvswitch "${BLUEPRINT_DIR}/configs/" 2>/dev/null || true
run_sudo ovs-vsctl show > "${BLUEPRINT_DIR}/configs/ovs-show.txt" 2>/dev/null || true

# TLDR config (dacă există)
[ -d "${TARGET_HOME}/.local/share/tldr" ] && echo "TLDR instalat: ${TARGET_HOME}/.local/share/tldr" > "${BLUEPRINT_DIR}/configs/tldr-info.txt" 2>/dev/null
which tldr > "${BLUEPRINT_DIR}/configs/tldr-path.txt" 2>/dev/null || true

# VirtualBox Guest Additions
{
    echo "=== VBoxGuest Module ==="
    lsmod | grep -i vbox 2>/dev/null || true
    echo -e "\n=== VBox Version ==="
    cat /opt/VBoxGuestAdditions*/AUTORUN.SH 2>/dev/null | head -5 || true
    VBoxControl --version 2>/dev/null || true
    echo -e "\n=== vboxsf Group ==="
    getent group vboxsf 2>/dev/null || true
} > "${BLUEPRINT_DIR}/configs/virtualbox-guest-additions.txt" 2>&1

ok "Configurări sistem diverse"

###############################################################################
# 11. FIȘIERE CUSTOM DIN HOME (PROIECTE, SCRIPTURI, LABS)
###############################################################################
header "11/12 · FIȘIERE UTILIZATOR DIN HOME"

# Inventar complet al home-ului (fără venv-uri și cache-uri)
find "${TARGET_HOME}" -maxdepth 5 \
    \( -path "*/venvs/*/lib" -o -path "*/.cache" -o -path "*/__pycache__" \
       -o -path "*/.local/lib" -o -path "*/.local/share/tldr" \
       -o -path "*/.npm" -o -path "*/.docker" -o -path "*/node_modules" \) -prune \
    -o -type f -print \
    > "${BLUEPRINT_DIR}/user/home-file-inventory.txt" 2>/dev/null

# Copiere fișiere relevante (scripturi, configs, labs, proiecte)
# Excludem binary blobs, cache-uri, și venv-uri
mkdir -p "${BLUEPRINT_DIR}/user/home-snapshot"
rsync -a --relative \
    --exclude='venvs/*/lib/' \
    --exclude='venvs/*/bin/' \
    --exclude='venvs/*/include/' \
    --exclude='venvs/*/share/' \
    --exclude='.cache/' \
    --exclude='__pycache__/' \
    --exclude='.local/lib/' \
    --exclude='.local/share/tldr/' \
    --exclude='.npm/' \
    --exclude='.docker/' \
    --exclude='node_modules/' \
    --exclude='*.pyc' \
    --exclude='.bash_history' \
    --include='*/' \
    --include='*.sh' --include='*.py' --include='*.yml' --include='*.yaml' \
    --include='*.json' --include='*.conf' --include='*.cfg' --include='*.txt' \
    --include='*.md' --include='*.html' --include='*.css' --include='*.js' \
    --include='*.service' --include='*.timer' --include='*.ini' \
    --include='*.ps1' --include='*.bat' --include='*.cmd' \
    --include='Dockerfile' --include='Makefile' --include='.env' \
    --include='docker-compose*' \
    --exclude='*' \
    "${TARGET_HOME}/" "${BLUEPRINT_DIR}/user/home-snapshot/" 2>/dev/null || {
        # Fallback dacă rsync nu e disponibil
        warn "rsync indisponibil, se folosește cp"
        find "${TARGET_HOME}" -maxdepth 4 \
            \( -name '*.sh' -o -name '*.py' -o -name '*.yml' -o -name '*.yaml' \
               -o -name '*.json' -o -name '*.conf' -o -name 'Dockerfile' \
               -o -name 'docker-compose*' -o -name 'Makefile' -o -name '*.md' \) \
            -not -path "*/venvs/*" -not -path "*/.cache/*" \
            -exec cp --parents {} "${BLUEPRINT_DIR}/user/home-snapshot/" \; 2>/dev/null
    }

ok "Fișiere utilizator inventariate și copiate"

###############################################################################
# 12. GENERARE SCRIPT DE REPRODUCERE (RECONSTITUIRE AUTOMATĂ)
###############################################################################
header "12/12 · GENERARE SCRIPT DE REPRODUCERE"

cat > "${BLUEPRINT_DIR}/scripts/reproduce-vm.sh" << 'REPRODUCE_EOF'
#!/usr/bin/env bash
###############################################################################
#  reproduce-vm.sh
#  ──────────────────────────────────────────────────────────────────────────
#  Script de RECONSTITUIRE a VM MININET-SDN din blueprint
#  SE RULEAZĂ pe un Ubuntu 24.04 LTS Server FRESH INSTALL cu user: stud
#
#  Utilizare:
#      tar xzf vm-blueprint-*.tar.gz
#      cd vm-blueprint-*/scripts/
#      chmod +x reproduce-vm.sh
#      sudo ./reproduce-vm.sh
###############################################################################

set -euo pipefail

BLUEPRINT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_USER="stud"
TARGET_HOME="/home/${TARGET_USER}"

RED='\033[0;31m'; GRN='\033[0;32m'; CYN='\033[0;36m'; BLD='\033[1m'; RST='\033[0m'
step_num=0
step() { step_num=$((step_num+1)); printf "\n${BLD}${CYN}[Pasul %02d]${RST} %s\n" "$step_num" "$*"; }

echo -e "${BLD}${CYN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   RECONSTITUIRE VM MININET-SDN din Blueprint            ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${RST}"

# Verificare root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Eroare: Scriptul trebuie rulat cu sudo!${RST}"
    exit 1
fi

# ── 1. Actualizare sistem ──
step "Actualizare sistem de bază"
apt-get update -qq
apt-get upgrade -y -qq

# ── 2. Adăugare repository-uri ──
step "Configurare repository-uri APT"
# Copiere surse
if [ -f "${BLUEPRINT_DIR}/packages/apt-sources.txt" ]; then
    echo "  → Se verifică surse APT suplimentare din blueprint..."
    # Restaurare keyrings
    if [ -d "${BLUEPRINT_DIR}/packages/apt-keyrings" ]; then
        mkdir -p /etc/apt/keyrings
        cp "${BLUEPRINT_DIR}/packages/apt-keyrings"/* /etc/apt/keyrings/ 2>/dev/null || true
    fi
    # Restaurare sources.list.d
    for f in "${BLUEPRINT_DIR}"/packages/apt-sources.list.d/*; do
        [ -f "$f" ] && cp "$f" /etc/apt/sources.list.d/ 2>/dev/null
    done
fi
apt-get update -qq 2>/dev/null || true

# ── 3. Instalare pachete ──
step "Instalare pachete (din apt-manual-packages.txt)"
if [ -f "${BLUEPRINT_DIR}/packages/apt-manual-packages.txt" ]; then
    xargs -a "${BLUEPRINT_DIR}/packages/apt-manual-packages.txt" apt-get install -y -qq 2>&1 | tail -5
    echo -e "  ${GRN}→ Pachete instalate cu succes${RST}"
else
    echo "  [WARN] Nu s-a găsit lista de pachete manuale!"
fi

# ── 4. Docker ──
step "Configurare Docker"
if [ -f "${BLUEPRINT_DIR}/docker/docker-info.txt" ]; then
    if ! command -v docker &>/dev/null; then
        echo "  → Instalare Docker Engine..."
        curl -fsSL https://get.docker.com | sh
    fi
    usermod -aG docker "${TARGET_USER}"
    [ -f "${BLUEPRINT_DIR}/docker/daemon.json" ] && cp "${BLUEPRINT_DIR}/docker/daemon.json" /etc/docker/
    systemctl enable --now docker
    
    # Pull imagini
    if [ -f "${BLUEPRINT_DIR}/docker/docker-images-pull-list.txt" ]; then
        echo "  → Pull imagini Docker..."
        while IFS= read -r img; do
            [ -n "$img" ] && docker pull "$img" 2>/dev/null && echo "    ✓ $img" || echo "    ✗ $img (skip)"
        done < "${BLUEPRINT_DIR}/docker/docker-images-pull-list.txt"
    fi
fi

# ── 5. Python venv ──
step "Configurare Python Virtual Environments"
for venv_req in "${BLUEPRINT_DIR}"/python/venvs/*/requirements.txt; do
    [ -f "$venv_req" ] || continue
    venv_name=$(basename "$(dirname "$venv_req")")
    venv_path="${TARGET_HOME}/venvs/${venv_name}"
    
    echo "  → Creare venv: ${venv_path}"
    su - "${TARGET_USER}" -c "
        mkdir -p ~/venvs
        python3 -m venv '${venv_path}'
        source '${venv_path}/bin/activate'
        pip install --upgrade pip
        pip install -r '${venv_req}'
    "
    echo -e "  ${GRN}→ venv ${venv_name} creat cu succes${RST}"
done

# ── 6. Configurări utilizator ──
step "Restaurare configurări utilizator (dotfiles)"
if [ -d "${BLUEPRINT_DIR}/user/dotfiles" ]; then
    for f in "${BLUEPRINT_DIR}/user/dotfiles"/.*; do
        fname=$(basename "$f")
        [[ "$fname" == "." || "$fname" == ".." ]] && continue
        if [ -d "$f" ]; then
            cp -r "$f" "${TARGET_HOME}/${fname}"
        else
            cp "$f" "${TARGET_HOME}/${fname}"
        fi
    done
    chown -R "${TARGET_USER}:${TARGET_USER}" "${TARGET_HOME}"
fi

# ── 7. Grupuri utilizator ──
step "Configurare grupuri utilizator"
for grp in docker wireshark vboxsf; do
    if getent group "$grp" &>/dev/null; then
        usermod -aG "$grp" "${TARGET_USER}" && echo "  → ${TARGET_USER} adăugat în grupul: $grp"
    fi
done

# ── 8. SSH Config ──
step "Restaurare configurare SSH"
[ -f "${BLUEPRINT_DIR}/security/sshd_config" ] && cp "${BLUEPRINT_DIR}/security/sshd_config" /etc/ssh/
[ -d "${BLUEPRINT_DIR}/security/sshd_config.d" ] && cp -r "${BLUEPRINT_DIR}/security/sshd_config.d" /etc/ssh/
systemctl restart sshd 2>/dev/null || true

# ── 9. Sudoers ──
step "Restaurare sudoers"
if [ -d "${BLUEPRINT_DIR}/security/sudoers.d" ]; then
    for f in "${BLUEPRINT_DIR}/security/sudoers.d"/*; do
        [ -f "$f" ] && cp "$f" /etc/sudoers.d/ && chmod 440 "/etc/sudoers.d/$(basename "$f")"
    done
fi

# ── 10. Bannere MOTD ──
step "Restaurare bannere și MOTD"
[ -f "${BLUEPRINT_DIR}/configs/issue" ] && cp "${BLUEPRINT_DIR}/configs/issue" /etc/issue
[ -f "${BLUEPRINT_DIR}/configs/issue.net" ] && cp "${BLUEPRINT_DIR}/configs/issue.net" /etc/issue.net
if [ -d "${BLUEPRINT_DIR}/configs/update-motd.d" ]; then
    cp "${BLUEPRINT_DIR}/configs/update-motd.d"/* /etc/update-motd.d/ 2>/dev/null
    chmod +x /etc/update-motd.d/* 2>/dev/null
fi

# ── 11. Wireshark ──
step "Configurare Wireshark (captură fără sudo)"
if command -v dumpcap &>/dev/null; then
    setcap 'cap_net_raw,cap_net_admin=eip' /usr/bin/dumpcap 2>/dev/null || true
fi

# ── 12. Sysctl ──
step "Restaurare sysctl"
[ -f "${BLUEPRINT_DIR}/configs/sysctl.conf" ] && cp "${BLUEPRINT_DIR}/configs/sysctl.conf" /etc/
[ -d "${BLUEPRINT_DIR}/configs/sysctl.d" ] && cp -r "${BLUEPRINT_DIR}/configs/sysctl.d"/* /etc/sysctl.d/ 2>/dev/null || true
sysctl --system 2>/dev/null || true

# ── 13. Servicii custom ──
step "Restaurare servicii systemd custom"
if [ -d "${BLUEPRINT_DIR}/services/custom-units" ]; then
    find "${BLUEPRINT_DIR}/services/custom-units" -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' \) | while read -r f; do
        fname=$(basename "$f")
        cp "$f" /etc/systemd/system/
        echo "  → Restaurat: $fname"
    done
    systemctl daemon-reload
fi

# ── 14. Docker compose files din home ──
step "Restaurare fișiere Docker Compose în home"
if [ -d "${BLUEPRINT_DIR}/docker/compose-files" ]; then
    cp -r "${BLUEPRINT_DIR}/docker/compose-files"/* "${TARGET_HOME}/" 2>/dev/null || true
    chown -R "${TARGET_USER}:${TARGET_USER}" "${TARGET_HOME}"
fi

# ── 15. Scripturi și fișiere proiect ──
step "Restaurare fișiere proiect din home-snapshot"
if [ -d "${BLUEPRINT_DIR}/user/home-snapshot" ]; then
    # Merge cu directorul home existent
    rsync -a "${BLUEPRINT_DIR}/user/home-snapshot/" "${TARGET_HOME}/" 2>/dev/null || \
        cp -r "${BLUEPRINT_DIR}/user/home-snapshot"/* "${TARGET_HOME}/" 2>/dev/null || true
    chown -R "${TARGET_USER}:${TARGET_USER}" "${TARGET_HOME}"
fi

# ── 16. Alternatives ──
step "Restaurare alternatives (editor implicit, etc.)"
if [ -f "${BLUEPRINT_DIR}/configs/alternatives.txt" ]; then
    while IFS=$'\t' read -r name path _priority; do
        [ -n "$name" ] && [ -n "$path" ] && [ -f "$path" ] && \
            update-alternatives --set "$name" "$path" 2>/dev/null || true
    done < <(grep -v '^$' "${BLUEPRINT_DIR}/configs/alternatives.txt")
fi

# ── Finalizare ──
echo -e "\n${BLD}${GRN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   ✅  RECONSTITUIRE COMPLETĂ!                           ║"
echo "║   Recomandare: sudo reboot                              ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${RST}"
REPRODUCE_EOF

chmod +x "${BLUEPRINT_DIR}/scripts/reproduce-vm.sh"
ok "Script de reproducere generat"

###############################################################################
# GENERARE RAPORT SUMAR
###############################################################################
header "GENERARE RAPORT SUMAR"

cat > "${BLUEPRINT_DIR}/README.md" << EOF
# VM Blueprint — MININET-SDN (Ubuntu 24.04 LTS)

**Data extracție:** ${TIMESTAMP}
**Hostname:** $(hostname 2>/dev/null)
**Kernel:** $(uname -r 2>/dev/null)
**User:** ${TARGET_USER}

## Structura Arhivei

\`\`\`
vm-blueprint-${TIMESTAMP}/
├── README.md                    ← Acest fișier
├── system/                      ← Info hardware, kernel, mount, locale
├── packages/                    ← Lista completă pachete (dpkg, apt, snap, pip)
│   ├── apt-manual-packages.txt  ← ⭐ Pachetele instalate manual
│   ├── dpkg-full-list.txt       ← Toate pachetele cu versiuni
│   ├── apt-sources.txt          ← Repository-uri APT
│   └── apt-keyrings/            ← Chei GPG pentru repo-uri
├── services/                    ← Servicii systemd (active, enabled, custom)
├── network/                     ← Configurație rețea (netplan, iptables, DNS)
├── docker/                      ← Docker config, imagini, compose files
│   ├── docker-info.txt          ← Versiune, imagini, rețele, volume
│   ├── docker-images-pull-list.txt ← Lista imagini pentru pull automat
│   └── compose-files/           ← Toate fișierele docker-compose
├── python/                      ← Python venvs cu requirements.txt
├── user/                        ← Dotfiles, crontabs, fișiere din home
│   ├── dotfiles/                ← .bashrc, .bash_aliases, .ssh/config, etc.
│   └── home-snapshot/           ← Scripturi, YAML, JSON, etc. din home
├── security/                    ← Utilizatori, grupuri, sudoers, sshd_config
├── configs/                     ← MOTD, issue, sysctl, alternatives, GRUB
│   ├── issue / issue.net        ← Bannere pre-login
│   └── update-motd.d/           ← Mesaje post-login
├── hardware/                    ← (rezervat)
└── scripts/
    └── reproduce-vm.sh          ← ⭐ SCRIPT RECONSTITUIRE AUTOMATĂ
\`\`\`

## Cum se reproduce VM-ul

1. Instalează Ubuntu 24.04 LTS Server (Minimal) pe VirtualBox
2. Creează user \`stud\` cu parola \`stud\` (cu drepturi sudo)
3. Configurează NAT + Port Forwarding (Host 2222 → Guest 22)
4. Transferă și dezarhivează:
   \`\`\`bash
   scp -P 2222 ${ARCHIVE_NAME} stud@127.0.0.1:~/
   ssh -p 2222 stud@127.0.0.1
   tar xzf ${ARCHIVE_NAME}
   cd vm-blueprint-${TIMESTAMP}/scripts/
   sudo ./reproduce-vm.sh
   \`\`\`
5. Reboot: \`sudo reboot\`
EOF

ok "README.md generat"

###############################################################################
# CREARE ARHIVĂ FINALĂ
###############################################################################
header "CREARE ARHIVĂ FINALĂ"

info "Se comprimă blueprint-ul..."
cd /tmp
tar czf "${ARCHIVE_PATH}" "vm-blueprint-${TIMESTAMP}/"
ARCHIVE_SIZE=$(du -sh "${ARCHIVE_PATH}" | cut -f1)

echo ""
echo -e "${BLD}${GRN}╔══════════════════════════════════════════════════════════╗${RST}"
echo -e "${BLD}${GRN}║   ✅  EXTRACȚIE COMPLETĂ!                                ║${RST}"
echo -e "${BLD}${GRN}╠══════════════════════════════════════════════════════════╣${RST}"
echo -e "${BLD}${GRN}║${RST}  Arhivă: ${BLD}${ARCHIVE_PATH}${RST}"
echo -e "${BLD}${GRN}║${RST}  Dimensiune: ${BLD}${ARCHIVE_SIZE}${RST}"
echo -e "${BLD}${GRN}║${RST}"
echo -e "${BLD}${GRN}║${RST}  Reconstituire:${RST}"
echo -e "${BLD}${GRN}║${RST}    tar xzf ${ARCHIVE_NAME}"
echo -e "${BLD}${GRN}║${RST}    cd vm-blueprint-*/scripts/"
echo -e "${BLD}${GRN}║${RST}    sudo ./reproduce-vm.sh"
echo -e "${BLD}${GRN}╚══════════════════════════════════════════════════════════╝${RST}"

# Curățare
rm -rf "${BLUEPRINT_DIR}"

echo ""
info "Blueprint extras cu succes. Copie-l pe Host cu:"
echo "    scp -P 2222 stud@127.0.0.1:~/${ARCHIVE_NAME} ."
