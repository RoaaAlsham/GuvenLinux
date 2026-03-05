# PardusGuard

**System Hardening & Security Assessment Tool for Pardus Linux**

TEKNOFEST 2026 | Development Category

---

PardusGuard is an open-source system hardening and security assessment tool built specifically for the [Pardus](https://www.pardus.org.tr/) Linux operating system. It bridges the gap between powerful but complex security tools and everyday users who lack the expertise to interpret their output or act on their recommendations.

## Features

- **Automated Security Scanning** — Six specialized scan engines covering ports, SSH, services, kernel hardening, file permissions, and user authentication
- **Risk Scoring** — Numeric score (0-100) with color-coded severity levels (Critical / High / Medium / Low / Info)
- **GTK4 Dashboard** — Modern graphical interface with 7 pages: Overview, Scan Results, Hardening Actions, Network View, Reports, Settings, and Logs
- **One-Click Hardening** — Apply recommended fixes automatically or step-by-step, all authenticated via PolicyKit
- **Report Export** — Full security reports in PDF and JSON formats
- **Audit Logging** — Every scan and fix action is logged for accountability

## Scan Engines

| Engine | Domain | Key Checks |
|--------|--------|------------|
| Port & Network Scanner | Network exposure | Open ports, listening services, dangerous ports |
| SSH Configuration Auditor | Remote access | PermitRootLogin, ciphers, MaxAuthTries |
| Service Auditor | Running services | Unnecessary services, root-context services |
| Kernel & OS Hardening | Kernel parameters | ASLR, SYN cookies, IP forwarding, core dumps |
| File Permission Auditor | Filesystem | SUID/SGID binaries, world-writable files, ownership |
| User & Authentication Auditor | User accounts | Empty passwords, UID 0 duplicates, sudoers |

## Requirements

- Pardus 25.0 (or Debian-based Linux)
- Python 3.10+
- GTK4 + PyGObject
- System tools: `ss`, `systemctl`, `nft`, `find`, `sysctl`

## Installation

### From .deb package (recommended)

```bash
sudo dpkg -i pardusguard_*.deb
```

### From source

```bash
git clone https://github.com/your-org/pardusguard.git
cd pardusguard
pip install -r requirements.txt
python -m src.main
```

## Project Structure

```
pardusguard/
├── src/
│   ├── main.py                  # Entry point
│   ├── main_window.py           # GTK4 application window
│   ├── scan_runner.py           # Orchestrates all 6 engines
│   ├── risk_scorer.py           # Scoring & classification
│   ├── fix_engine.py            # Remediation executor
│   ├── action_registry.py       # Registry of all fix actions
│   ├── report_renderer.py       # PDF/JSON export
│   ├── log_manager.py           # Audit logging
│   ├── config_manager.py        # Settings persistence
│   ├── engines/
│   │   ├── port_scanner.py
│   │   ├── ssh_auditor.py
│   │   ├── service_auditor.py
│   │   ├── kernel_hardening.py
│   │   ├── file_permission.py
│   │   └── user_auditor.py
│   └── ui/
│       ├── dashboard.py
│       ├── scan_results.py
│       ├── hardening_page.py
│       ├── network_view.py
│       ├── reports_page.py
│       ├── settings_page.py
│       └── logs_page.py
├── data/
│   ├── org.pardus.pardusguard.policy
│   ├── pardusguard.desktop
│   └── risk_weights.json
├── tests/
├── debian/
├── docs/
├── setup.py
├── requirements.txt
└── LICENSE
```

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.10+ |
| GUI | GTK4 + PyGObject |
| Privilege Escalation | PolicyKit + pkexec |
| Database | SQLite3 |
| Report Export | ReportLab (PDF) + JSON |
| Testing | pytest + pytest-cov |
| Packaging | debhelper + dh-python |
| CI/CD | GitHub Actions |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute.

## License

This project is licensed under the GNU General Public License v3.0 — see the [LICENSE](LICENSE) file for details.

## Team

TEKNOFEST 2026 Development Category Entry

---

*Scan. Score. Harden. Educate.*
