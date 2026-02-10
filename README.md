# WSL2 SDN Kernel + Mininet Lab Setup

Pre-compiled WSL2 kernel with **Open vSwitch**, **QoS schedulers**, and full
networking module stack for SDN/Mininet labs. Replaces 30-minute local
compilation with a ~15 MB download.

## Quick Start

```powershell
# Run as Administrator in PowerShell:
powershell -ExecutionPolicy Bypass -File .\setup-mininet-wsl2.ps1
```

The script will:
1. Enable WSL2 + install Ubuntu 24.04
2. **Download** pre-compiled kernel from GitHub Releases (not compile!)
3. Configure `.wslconfig` with custom kernel
4. Install full SDN stack: Mininet, OVS, Docker, Scapy, tshark, nmap...
5. Create Python venv `compnet` with os-ken, grpcio, flask, paramiko...
6. Configure aliases, MOTD, SSH, port forwarding

**Total time: ~10 minutes** (vs 30-60 min with local compilation)

## Script Options

```powershell
# Full install (default):
.\setup-mininet-wsl2.ps1

# Skip kernel (already installed):
.\setup-mininet-wsl2.ps1 -SkipKernel

# Only software stack (WSL2 + kernel already configured):
.\setup-mininet-wsl2.ps1 -Phase3Only

# Use specific kernel archive (offline / custom build):
.\setup-mininet-wsl2.ps1 -LocalKernel "C:\path\to\wsl2-sdn-kernel.tar.gz"

# Point to a different GitHub repo:
.\setup-mininet-wsl2.ps1 -GithubRepo "myuser/my-kernel-repo"
```

## What's in the kernel

All built as **loadable modules** (auto-loaded at WSL boot):

| Category | Modules |
|----------|---------|
| Open vSwitch | `openvswitch`, GRE, VXLAN, Geneve |
| QoS | HTB, NETEM, HFSC, TBF, RED, SFQ, PRIO, INGRESS |
| Networking | bridge, VETH, VLAN 802.1Q, dummy |
| Firewall | nf_tables, nf_nat, nf_conntrack |
| Advanced | macvlan, ipvlan, bonding, team |

## Building a new kernel release

### Automatic (GitHub Actions)

```bash
git tag v1.0.0
git push origin v1.0.0
```

This triggers the CI pipeline which compiles the kernel on Ubuntu 24.04
runners and publishes a Release with the `wsl2-sdn-kernel-*.tar.gz` archive.

### Manual trigger

Go to **Actions** > **Build WSL2 SDN Kernel** > **Run workflow**.
You can specify a different kernel branch (e.g. `linux-msft-wsl-6.1.y`).

## Windows 10 vs 11

| Feature | Windows 10 | Windows 11 |
|---------|-----------|------------|
| Mininet internal topologies | OK | OK |
| Docker containers | OK | OK |
| Broadcast/multicast to LAN | NO (NAT only) | Partial (mirrored mode) |
| Bridged networking | NO | YES (WSL 2.5.6+) |

The script auto-detects Windows version and configures optimally.

## Repository structure

```
.github/workflows/build-kernel.yml   # CI: compile + release
setup-mininet-wsl2.ps1               # Main setup script
README.md                            # This file
```

## Credits

- Kernel source: [microsoft/WSL2-Linux-Kernel](https://github.com/microsoft/WSL2-Linux-Kernel)
- VM blueprint: MININET-SDN (Ubuntu 24.04) - ASE-CSIE Networking Seminars
