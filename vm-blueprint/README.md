# VM Blueprint — MININET-SDN (Ubuntu 24.04 LTS)

**Data extracție:** 2026-02-10_181910
**Hostname:** mininet-vm
**Kernel:** 6.8.0-100-generic
**User:** stud

## Structura Arhivei

```
vm-blueprint-2026-02-10_181910/
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
```

## Cum se reproduce VM-ul

1. Instalează Ubuntu 24.04 LTS Server (Minimal) pe VirtualBox
2. Creează user `stud` cu parola `stud` (cu drepturi sudo)
3. Configurează NAT + Port Forwarding (Host 2222 → Guest 22)
4. Transferă și dezarhivează:
   ```bash
   scp -P 2222 vm-blueprint-2026-02-10_181910.tar.gz stud@127.0.0.1:~/
   ssh -p 2222 stud@127.0.0.1
   tar xzf vm-blueprint-2026-02-10_181910.tar.gz
   cd vm-blueprint-2026-02-10_181910/scripts/
   sudo ./reproduce-vm.sh
   ```
5. Reboot: `sudo reboot`
