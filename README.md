# KQL Hunter

> Auto-curated library of KQL (Kusto Query Language) queries collected daily from public GitHub repositories.

[![Daily Scan](https://github.com/YOUR_USER/kql-hunter/actions/workflows/daily-scan.yml/badge.svg)](https://github.com/YOUR_USER/kql-hunter/actions/workflows/daily-scan.yml)

**Live site →** https://YOUR_USER.github.io/kql-hunter

---

## How it works

1. **GitHub Actions** runs `scripts/scan_queries.py` every day at 02:00 UTC
2. The script searches GitHub's public code index for `.kql` files using targeted queries
3. Valid KQL files are downloaded, adapted with a standard header, and stored under `queries/`
4. `queries/index.json` is updated and committed back to the repo
5. GitHub Pages serves `docs/index.html` which reads the index and renders the query library

## Repo structure

```
kql-hunter/
├── .github/workflows/daily-scan.yml  # Scheduled GH Actions workflow
├── scripts/
│   └── scan_queries.py               # Scanner + adapter
├── queries/
│   ├── index.json                    # Full metadata index (auto-generated)
│   └── *.kql                        # Individual query files (auto-generated)
└── docs/
    └── index.html                    # Static query browser (GitHub Pages)
```

## Setup

1. Fork / clone this repo
2. Enable **GitHub Pages** → Source: `docs/` folder on `main` branch
3. The `GITHUB_TOKEN` secret is available automatically in Actions — no extra setup needed
4. Trigger the workflow manually once to seed the library: **Actions → Daily Scan → Run workflow**

## Categories

| Category | KQL Tables |
|---|---|
| Identity & Access | `SigninLogs`, `AuditLogs`, `IdentityLogonEvents` |
| Endpoint Security | `SecurityEvent`, `DeviceEvents`, `DeviceProcessEvents` |
| Network | `CommonSecurityLog`, `DeviceNetworkEvents` |
| Cloud / Azure | `AzureActivity`, `AzureDiagnostics` |
| Microsoft 365 | `OfficeActivity`, `EmailEvents`, `CloudAppEvents` |
| Linux / OS | `Syslog` |
| Threat Intelligence | `ThreatIntelligenceIndicator` |
| Alerts & Incidents | `SecurityAlert`, `SecurityIncident` |

## Attribution

All queries are sourced from public GitHub repositories. Each query retains a comment header with the original source URL and collection date. This project does not claim ownership of any collected query.
