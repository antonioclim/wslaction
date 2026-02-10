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
