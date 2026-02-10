#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# ==============================================================================
# CompNet Kit — MININET-SDN (Ubuntu) bootstrap & audit script
# - installs missing OS packages used across the kit
# - prepares a Python venv with optional dependencies
# - applies "compatibility fixes" inside the kit (symlinks + docker-compose patches)
# - performs basic sanity checks
#
# Designed for Ubuntu 24.04 LTS Server (headless) inside VirtualBox.
# Run as the normal user; the script will use sudo where required.
# ==============================================================================

SCRIPT_NAME="$(basename "$0")"

log()  { printf "[%s] %s\n" "INFO" "$*"; }
warn() { printf "[%s] %s\n" "WARN" "$*" >&2; }
err()  { printf "[%s] %s\n" "ERROR" "$*" >&2; }

SUDO="sudo"
if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  SUDO=""
fi

usage() {
  cat <<'EOF'
Usage:
  compnet_mininetvm_setup.sh [options]

Options:
  --kit-root PATH        Path to the kit root (folder containing AUDIT_SCRIPTS.md).
                         If omitted, the script will try to auto-detect from the current directory.
  --skip-apt             Skip APT package checks/installs.
  --skip-python          Skip Python venv + pip dependency install.
  --skip-kit-fixes       Skip kit compatibility fixes (symlinks + docker-compose patches).
  --self-test            Run lightweight self-tests (imports, versions, docker compose syntax).
  -h, --help             Show this help.

Examples:
  ./compnet_mininetvm_setup.sh --self-test
  ./compnet_mininetvm_setup.sh --kit-root ~/compnet-2025-redo-main --self-test
EOF
}

KIT_ROOT=""
DO_APT=1
DO_PY=1
DO_FIXES=1
DO_TEST=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --kit-root) KIT_ROOT="${2:-}"; shift 2 ;;
    --skip-apt) DO_APT=0; shift ;;
    --skip-python) DO_PY=0; shift ;;
    --skip-kit-fixes) DO_FIXES=0; shift ;;
    --self-test) DO_TEST=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) err "Unknown argument: $1"; usage; exit 2 ;;
  esac
done

require_cmd() {
  local c="$1"
  command -v "$c" >/dev/null 2>&1
}

install_apt_pkg() {
  local pkg="$1"
  if dpkg -s "$pkg" >/dev/null 2>&1; then
    return 0
  fi
  log "Installing APT package: $pkg"
  # best-effort install; continue if a package is unavailable (e.g., custom images)
  if ! ${SUDO} DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" >/dev/null; then
    warn "Could not install package '$pkg' (continuing)."
    return 1
  fi
  return 0
}

detect_kit_root() {
  # If explicitly provided and valid, use it.
  if [[ -n "${KIT_ROOT}" ]]; then
    if [[ -f "${KIT_ROOT}/AUDIT_SCRIPTS.md" ]]; then
      echo "${KIT_ROOT}"
      return 0
    fi
    warn "Provided --kit-root does not look like the kit root (AUDIT_SCRIPTS.md not found): ${KIT_ROOT}"
    return 1
  fi

  # Try from current directory, walking upwards.
  local d="$PWD"
  while [[ "$d" != "/" ]]; do
    if [[ -f "${d}/AUDIT_SCRIPTS.md" && -d "${d}/assets" ]]; then
      echo "$d"
      return 0
    fi
    d="$(dirname "$d")"
  done

  # Fallback: common locations.
  for cand in "$HOME/compnet-2025-redo-main" "$HOME/compnet-2025" "$HOME/compnet" "$HOME/v3_compnet-2025-redo-main+EU/compnet-2025-redo-main"; do
    if [[ -f "${cand}/AUDIT_SCRIPTS.md" ]]; then
      echo "$cand"
      return 0
    fi
  done

  return 1
}

create_symlink() {
  local link_abs="$1"
  local target_abs="$2"

  if [[ ! -e "$target_abs" ]]; then
    warn "Target missing, cannot link: $target_abs"
    return 1
  fi

  local link_dir
  link_dir="$(dirname "$link_abs")"
  ${SUDO} mkdir -p "$link_dir"

  # Use relative link if possible (nicer), otherwise absolute.
  local rel_target
  if command -v realpath >/dev/null 2>&1; then
    rel_target="$(realpath --relative-to="$link_dir" "$target_abs" 2>/dev/null || true)"
  else
    rel_target=""
  fi
  if [[ -z "$rel_target" ]]; then
    rel_target="$target_abs"
  fi

  # If link already exists and points correctly, do nothing.
  if [[ -L "$link_abs" ]]; then
    local current
    current="$(readlink "$link_abs" || true)"
    if [[ "$current" == "$rel_target" || "$current" == "$target_abs" ]]; then
      return 0
    fi
  fi

  ${SUDO} ln -sfn "$rel_target" "$link_abs"
  log "Symlink: ${link_abs} -> ${rel_target}"
}

write_file() {
  local path="$1"
  local mode="${2:-0644}"
  shift 2 || true
  local content="$*"
  ${SUDO} mkdir -p "$(dirname "$path")"
  # shellcheck disable=SC2001
  printf "%s" "$content" | ${SUDO} tee "$path" >/dev/null
  ${SUDO} chmod "$mode" "$path"
}

patch_compose_python_deps() {
  local kit="$1"

  # Patches are applied in-place, with a one-time .orig backup.
  # We keep changes minimal: wrap the existing python command with "sh -c 'pip install ... && python ...'".
  python3 - <<'PY' "$kit"
import os, shutil, sys
from pathlib import Path

kit = Path(sys.argv[1])

PATCHES = [
    # (compose_rel_path, service_name, pip_pkgs)
    ("assets/course/C11/assets/scenario-dns-ttl-caching/docker-compose.yml", "client", ["dnspython"]),
    ("assets/course/C11/assets/scenario-ftp-baseline/docker-compose.yml", "ftp", ["pyftpdlib"]),
    ("assets/course/C11/assets/scenario-ftp-nat-firewall/docker-compose.yml", "ftp", ["pyftpdlib"]),
    ("assets/course/C11/assets/scenario-ssh-provision/docker-compose.yml", "controller", ["paramiko"]),
]

def wrap_command(cmd, pip_pkgs):
    # cmd may be list ["python","script.py",...]
    # or string "python script.py ..."
    pip = " ".join(pip_pkgs)
    if isinstance(cmd, list) and cmd:
        # avoid double patching
        if any("pip" in str(x) for x in cmd):
            return cmd
        # best effort: recognise python/python3
        py = cmd[0]
        rest = " ".join(cmd[1:])
        return ["sh", "-c", f"pip install -q {pip} && {py} {rest}"]
    if isinstance(cmd, str):
        if "pip install" in cmd:
            return cmd
        return f"sh -c 'pip install -q {pip} && {cmd}'"
    return cmd

for rel, svc, pkgs in PATCHES:
    f = kit / rel
    if not f.exists():
        continue

    orig = f.with_suffix(f.suffix + ".orig")
    if not orig.exists():
        shutil.copy2(f, orig)

    # Extremely small YAML loader/writer without format preservation.
    import yaml
    data = yaml.safe_load(f.read_text(encoding="utf-8", errors="ignore"))
    if not isinstance(data, dict) or "services" not in data:
        continue
    services = data.get("services") or {}
    if svc not in services or not isinstance(services[svc], dict):
        continue

    before = services[svc].get("command")
    after = wrap_command(before, pkgs)
    if before == after:
        continue
    services[svc]["command"] = after

    f.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    print(f"[PATCH] {rel}: service '{svc}' command wrapped with pip install {pkgs}")
PY
}

ensure_bashrc_venv_autoactivate() {
  local user_name="$1"
  local home_dir="$2"
  local venv_path="$3"

  local bashrc="${home_dir}/.bashrc"
  local marker_begin="# >>> compnet-venv auto-activation >>>"
  local marker_end="# <<< compnet-venv auto-activation <<<"

  if [[ ! -f "$bashrc" ]]; then
    touch "$bashrc"
    chown "$user_name":"$user_name" "$bashrc" || true
  fi

  if grep -Fq "$marker_begin" "$bashrc"; then
    return 0
  fi

  cat >> "$bashrc" <<EOF

${marker_begin}
# Auto-activate the CompNet virtual environment for the networking kit.
if [ -d "${venv_path}" ] && [ -f "${venv_path}/bin/activate" ]; then
  # shellcheck disable=SC1090
  source "${venv_path}/bin/activate"
fi
${marker_end}
EOF

  log "Added CompNet venv auto-activation block to ${bashrc} (you may need to log out/in)."
}

main() {
  local user_name="${SUDO_USER:-$USER}"
  local home_dir
  home_dir="$(eval echo "~${user_name}")"

  log "Running as user: ${user_name} (home: ${home_dir})"

  if [[ "${DO_APT}" -eq 1 ]]; then
    log "Updating APT indexes..."
    ${SUDO} apt-get update -y >/dev/null

    # Prevent interactive prompt for tshark capture permissions on Debian/Ubuntu.
    if ! dpkg -s wireshark-common >/dev/null 2>&1; then
      ${SUDO} bash -c "echo 'wireshark-common wireshark-common/install-setuid boolean true' | debconf-set-selections" || true
    fi

    # Core tools used across tutorials/courses
    local pkgs=(
      git curl wget unzip zip ca-certificates openssh-server
      net-tools dnsutils iputils-ping traceroute tcpdump tshark
      netcat-openbsd socat iperf3 telnet
      nmap nikto
      iproute2 iptables
      python3 python3-pip python3-venv python3-dev python-is-python3 python3-yaml
      openvswitch-switch openvswitch-testcontroller
      mininet
      default-jre-headless graphviz
      mosquitto-clients vim-common
    )

    for p in "${pkgs[@]}"; do
      install_apt_pkg "$p" || true
    done

    # Docker (only if missing)
    if ! require_cmd docker; then
      warn "Docker not found; attempting to install docker.io + docker compose plugin (Ubuntu repo)."
      install_apt_pkg docker.io || true
      install_apt_pkg docker-compose-plugin || true
    fi

    # Convenience: provide legacy docker-compose command if missing.
    if ! require_cmd docker-compose && require_cmd docker; then
      write_file "/usr/local/bin/docker-compose" "0755" \
'#!/usr/bin/env bash
exec docker compose "$@"
'
      log "Installed docker-compose wrapper (/usr/local/bin/docker-compose) -> docker compose"
    fi

    # Group membership (best effort; takes effect after re-login).
    if getent group docker >/dev/null 2>&1; then
      if ! id -nG "$user_name" | tr ' ' '\n' | grep -qx docker; then
        ${SUDO} usermod -aG docker "$user_name" || true
        warn "Added '${user_name}' to group 'docker' (re-login required for effect)."
      fi
    fi
    if getent group wireshark >/dev/null 2>&1; then
      if ! id -nG "$user_name" | tr ' ' '\n' | grep -qx wireshark; then
        ${SUDO} usermod -aG wireshark "$user_name" || true
        warn "Added '${user_name}' to group 'wireshark' (re-login required for effect)."
      fi
    fi
  else
    log "Skipping APT step (--skip-apt)."
  fi

  # Python venv with optional deps
  local venv_path="${home_dir}/venvs/compnet"
  if [[ "${DO_PY}" -eq 1 ]]; then
    if [[ ! -d "${venv_path}" ]]; then
      log "Creating Python venv: ${venv_path}"
      ${SUDO} -u "$user_name" python3 -m venv "${venv_path}"
    fi

    log "Installing/upgrading Python packages in venv..."
    # Activate in a subshell to avoid polluting current shell environment.
    ${SUDO} -u "$user_name" bash -lc "
      set -e
      source '${venv_path}/bin/activate'
      python -m pip install -q --upgrade pip setuptools wheel
      if [[ -f '${KIT_ROOT:-}/requirements-optional.txt' ]]; then
        python -m pip install -q -r '${KIT_ROOT:-}/requirements-optional.txt'
      else
        # fallback: install the kit's optional list explicitly
        python -m pip install -q requests Flask flask-sock dnspython dnslib pyftpdlib paramiko paho-mqtt scapy grpcio grpcio-tools os-ken
      fi
      # course C12 local mailbox helper (present in kit)
      python -m pip install -q 'aiosmtpd>=1.4.6' || true
    "

    # Optional: auto-activate venv on login (matches the VM manual).
    ensure_bashrc_venv_autoactivate "$user_name" "$home_dir" "$venv_path"
  else
    log "Skipping Python step (--skip-python)."
  fi

  local kit_detected=""
  kit_detected="$(detect_kit_root || true)"
  if [[ -n "$kit_detected" ]]; then
    KIT_ROOT="$kit_detected"
    log "Kit root detected: ${KIT_ROOT}"
  else
    warn "Kit root not detected. If you want symlinks/docker-compose patches, rerun with --kit-root PATH."
  fi

  if [[ "${DO_FIXES}" -eq 1 && -n "${KIT_ROOT}" ]]; then
    log "Applying kit compatibility fixes (symlinks + docker-compose patches)..."

    # ---- Symlinks for filenames used in markdown (underscores/index_*) ----
    # Format: link_rel|target_rel (both relative to KIT_ROOT)
    local mappings=(
      # Course assets
      "assets/course/C03/assets/scenario-scapy-icmp/icmp_ping.py|assets/course/C03/assets/scenario-scapy-icmp/icmp-ping.py"
      "assets/course/C05/assets/scenario-cidr-basic/cidr_calc.py|assets/course/C05/assets/scenario-cidr-basic/cidr-calc.py"
      "assets/course/C05/assets/scenario-subnetting-flsm/flsm_split.py|assets/course/C05/assets/scenario-subnetting-flsm/flsm-split.py"
      "assets/course/C05/assets/scenario-vlsm/vlsm_alloc.py|assets/course/C05/assets/scenario-vlsm/vlsm-alloc.py"
      "assets/course/C05/assets/scenario-ipv6-shortening/ipv6_norm.py|assets/course/C05/assets/scenario-ipv6-shortening/ipv6-norm.py"
      "assets/course/C06/assets/scenario-nat-linux/nat_demo.sh|assets/course/C06/assets/scenario-nat-linux/nat-demo.sh"
      "assets/course/C07/assets/scenario-djikstra/dijkstra.py|assets/course/C07/assets/scenario-djikstra/djikstra.py"
      "assets/course/C07/assets/scenario-mininet-routing/triangle-net.py|assets/course/C07/assets/scenario-mininet-routing/tringle-net.py"

      # Tutorial S02
      "assets/tutorial/S02/index_tcp-client_template.py|assets/tutorial/S02/5_tcp-client_template.py"
      "assets/tutorial/S02/index_udp-server_example.py|assets/tutorial/S02/7_udp-server_example.py"
      "assets/tutorial/S02/index_udp-server_template.py|assets/tutorial/S02/8_udp-server_template.py"
      "assets/tutorial/S02/index_udp-client_example.py|assets/tutorial/S02/9_udp-client_example.py"
      "assets/tutorial/S02/index_udp-client_template.py|assets/tutorial/S02/10_udp-client_template.py"

      # Tutorial S03
      "assets/tutorial/S03/index_tcp-multiclient-server_example.py|assets/tutorial/S03/1_tcp-multiclient-server_example.py"
      "assets/tutorial/S03/index_tcp-multiclient-server_template.py|assets/tutorial/S03/2_tcp-multiclient-server_template.py"
      "assets/tutorial/S03/5_udp-multicast/index_udp-multicast_sender_example.py|assets/tutorial/S03/5_udp-multicast/5a_udp-multicast_sender_example.py"
      "assets/tutorial/S03/5_udp-multicast/index_udp-multicast_receiver_example.py|assets/tutorial/S03/5_udp-multicast/5b_udp-multicast_receiver_example.py"
      "assets/tutorial/S03/5_udp-multicast/index_udp-multicast_receiver_template.py|assets/tutorial/S03/5_udp-multicast/5c_udp-multicast_receiver_template.py"
      "assets/tutorial/S03/6_udp-anycast/index_udp-anycast_server_example.py|assets/tutorial/S03/6_udp-anycast/6a_udp-anycast_server_example.py"
      "assets/tutorial/S03/6_udp-anycast/index_udp-anycast_client_example.py|assets/tutorial/S03/6_udp-anycast/6b_udp-anycast_client_example.py"
      "assets/tutorial/S03/6_udp-anycast/index_udp-anycast_server_template.py|assets/tutorial/S03/6_udp-anycast/6c_idp-anycast_template.py"

      # Tutorial S04 — text protocol over TCP
      "assets/tutorial/S04/1_text-proto_tcp/index_text-proto_tcp-server_example.py|assets/tutorial/S04/1_text-proto_tcp/1a_text-proto_tcp-server_example.py"
      "assets/tutorial/S04/1_text-proto_tcp/index_text-proto_tcp-client_example.py|assets/tutorial/S04/1_text-proto_tcp/1b_text-proto_tcp-client_example.py"
      "assets/tutorial/S04/1_text-proto_tcp/index_text-proto_tcp-server_template.py|assets/tutorial/S04/1_text-proto_tcp/1c_text-proto_tcp-server_template.py"
      # Tutorial S04 — binary protocol over TCP
      "assets/tutorial/S04/2_binary-proto_tcp/index_binary-proto_tcp-server_example.py|assets/tutorial/S04/2_binary-proto_tcp/2a_binary-proto_tcp-server_example.py"
      "assets/tutorial/S04/2_binary-proto_tcp/index_binary-proto_tcp-client_example.py|assets/tutorial/S04/2_binary-proto_tcp/2b_binary-proto_tcp-client_example.py"
      "assets/tutorial/S04/2_binary-proto_tcp/index_binary-proto_tcp-server_template.py|assets/tutorial/S04/2_binary-proto_tcp/2c_binary-proto_tcp-server_template.py"
      # Tutorial S04 — UDP proto
      "assets/tutorial/S04/3_proto_udp/index_udp-proto_server_example.py|assets/tutorial/S04/3_proto_udp/3a_udp-proto_server_example.py"
      "assets/tutorial/S04/3_proto_udp/index_udp-proto_client_example.py|assets/tutorial/S04/3_proto_udp/3b_udp-proto_client_example.py"
      "assets/tutorial/S04/3_proto_udp/index_udp-proto_client_template.py|assets/tutorial/S04/3_proto_udp/3c_udp-proto_client_template.py"
      "assets/tutorial/S04/3_proto_udp/index_udp-proto_server_template.py|assets/tutorial/S04/3_proto_udp/3c_udp-proto_server_template.py"

      # Tutorial S05 — Mininet topology
      "assets/tutorial/S05/3_network-simulation/index_mininet-topology.py|assets/tutorial/S05/3_network-simulation/3b_mininet-topology.py"

      # Tutorial S06 — routing + SDN
      "assets/tutorial/S06/1_routing/index_routing-triangle_topology.py|assets/tutorial/S06/1_routing/1b_routing-triangle_topology.py"
      "assets/tutorial/S06/2_sdn/index_sdn_topo_switch.py|assets/tutorial/S06/2_sdn/2b_sdn_topo_switch.py"
      "assets/tutorial/S06/2_sdn/index_sdn_os-ken_controller.py|assets/tutorial/S06/2_sdn/2c_sdn-os-ken_controller.py"
      "assets/tutorial/S06/2_sdn/index_sdn_os-keb_controller.py|assets/tutorial/S06/2_sdn/2c_sdn-os-ken_controller.py"

      # Tutorial S07 — sniffing/scanning
      "assets/tutorial/S07/1_sniffing/packet_sniffer.py|assets/tutorial/S07/1_sniffing/1b_packet_sniffer.py"
      "assets/tutorial/S07/2_packet-filter/packet_filter.py|assets/tutorial/S07/2_packet-filter/2a_packet-filter.py"
      "assets/tutorial/S07/3_port-scanning/port_scanner.py|assets/tutorial/S07/3_port-scanning/3a_port_scanner.py"
      "assets/tutorial/S07/4_scan-detector/detect_scan.py|assets/tutorial/S07/4_scan-detector/4a_detect-scan.py"
      "assets/tutorial/S07/5_mini-ids/mini_ids.py|assets/tutorial/S07/5_mini-ids/5a_mini-ids.py"

      # Tutorial S08 — HTTP servers
      "assets/tutorial/S08/2_simple-http/simple_http_builtin.py|assets/tutorial/S08/2_simple-http/2b_simple-http-builtin_example.py"
      "assets/tutorial/S08/3_socket-http/socket_http_server.py|assets/tutorial/S08/3_socket-http/3b_socket-http-server_example.py"

      # Tutorial S09 — FTP
      "assets/tutorial/S09/1_ftp/pyftpd_client.py|assets/tutorial/S09/1_ftp/1d_pyftpd-client.py"
      "assets/tutorial/S09/2_custom-pseudo-ftp/pseudo_ftp_server.py|assets/tutorial/S09/2_custom-pseudo-ftp/2b_pseudo-ftp-server.py"
      "assets/tutorial/S09/2_custom-pseudo-ftp/pseudo_ftp_client.py|assets/tutorial/S09/2_custom-pseudo-ftp/2c_pseudo-ftp-client.py"
    )

    local m
    for m in "${mappings[@]}"; do
      local link_rel="${m%%|*}"
      local target_rel="${m#*|}"
      create_symlink "${KIT_ROOT}/${link_rel}" "${KIT_ROOT}/${target_rel}" || true
    done

    # Wrapper scripts referenced in docs but absent in kit (course C07 mininet routing).
    local routing_dir="${KIT_ROOT}/assets/course/C07/assets/scenario-mininet-routing"
    if [[ -d "$routing_dir" ]]; then
      if [[ ! -f "${routing_dir}/run-link-down.sh" ]]; then
        write_file "${routing_dir}/run-link-down.sh" "0755" \
'#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
sudo python3 tringle-net.py link-down
'
        log "Created wrapper: ${routing_dir}/run-link-down.sh"
      fi
      if [[ ! -f "${routing_dir}/run-asymmetric.sh" ]]; then
        write_file "${routing_dir}/run-asymmetric.sh" "0755" \
'#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
sudo python3 tringle-net.py asymmetric
'
        log "Created wrapper: ${routing_dir}/run-asymmetric.sh"
      fi
    fi

    # Patch docker-compose scenarios where Python deps are missing inside containers.
    patch_compose_python_deps "${KIT_ROOT}"

  else
    log "Skipping kit fixes (--skip-kit-fixes or kit not detected)."
  fi

  if [[ "${DO_TEST}" -eq 1 ]]; then
    log "Running self-tests (best effort)..."

    # Versions / commands
    if require_cmd mn; then
      log "Mininet: $(mn --version 2>/dev/null || true)"
    else
      warn "Mininet not found in PATH (mn)."
    fi
    if require_cmd ovs-vsctl; then
      log "Open vSwitch: $(ovs-vsctl --version 2>/dev/null | head -n 1 || true)"
    else
      warn "Open vSwitch not found (ovs-vsctl)."
    fi
    if require_cmd docker; then
      log "Docker: $(docker --version 2>/dev/null || true)"
      if docker compose version >/dev/null 2>&1; then
        log "Docker Compose: $(docker compose version 2>/dev/null || true)"
      else
        warn "'docker compose' not available."
      fi
    else
      warn "Docker not found."
    fi

    # Python module imports inside venv (if available)
    if [[ -d "${venv_path}" && -f "${venv_path}/bin/activate" ]]; then
      ${SUDO} -u "$user_name" bash -lc "
        set -e
        source '${venv_path}/bin/activate'
        python - <<'PY'
mods = [
  ('requests','requests'),
  ('flask','Flask'),
  ('flask_sock','flask-sock'),
  ('dns','dnspython'),
  ('dnslib','dnslib'),
  ('pyftpdlib','pyftpdlib'),
  ('paramiko','paramiko'),
  ('paho.mqtt.client','paho-mqtt'),
  ('scapy.all','scapy'),
  ('grpc','grpcio'),
  ('grpc_tools','grpcio-tools'),
  ('os_ken','os-ken'),
]
ok = True
for mod, pkg in mods:
    try:
        __import__(mod)
    except Exception as e:
        ok = False
        print(f'[MISSING] {mod} (pip: {pkg}) -> {e}')
if ok:
    print('[OK] Python optional dependencies import correctly.')
PY
      " || warn "Python import self-test encountered issues."
    fi

    # Compose files lint (if kit detected)
    if [[ -n "${KIT_ROOT}" && -d "${KIT_ROOT}" && -x "$(command -v docker)" ]]; then
      # Only test the patched ones (syntax check via 'docker compose config' from those folders).
      local compose_dirs=(
        "assets/course/C11/assets/scenario-dns-ttl-caching"
        "assets/course/C11/assets/scenario-ftp-baseline"
        "assets/course/C11/assets/scenario-ftp-nat-firewall"
        "assets/course/C11/assets/scenario-ssh-provision"
      )
      local d
      for d in "${compose_dirs[@]}"; do
        if [[ -f "${KIT_ROOT}/${d}/docker-compose.yml" ]]; then
          log "Compose config check: ${d}"
          (cd "${KIT_ROOT}/${d}" && docker compose config >/dev/null) || warn "Compose config failed for ${d}"
        fi
      done
    fi

    log "Self-tests completed."
  fi

  log "Done."
  if [[ "${DO_APT}" -eq 1 ]]; then
    warn "If group memberships were changed (docker/wireshark), log out and log back in (or reboot) for them to take effect."
  fi
}

main "$@"
