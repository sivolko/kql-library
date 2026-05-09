#!/usr/bin/env python3
"""
KQL Hunter - Scans GitHub public repos for KQL queries,
adapts them with consistent structure, and stores to index.
"""

import os
import re
import json
import time
import hashlib
import logging
import requests
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
QUERIES_DIR = Path(__file__).parent.parent / "queries"
INDEX_FILE = QUERIES_DIR / "index.json"

HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}
if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"

# KQL search terms to find interesting queries across GitHub
SEARCH_QUERIES = [
    "extension:kql SecurityEvent",
    "extension:kql SigninLogs",
    "extension:kql AuditLogs",
    "extension:kql DeviceEvents",
    "extension:kql IdentityLogonEvents",
    "extension:kql AzureActivity",
    "extension:kql CommonSecurityLog",
    "extension:kql OfficeActivity",
    "extension:kql Syslog",
    "extension:kql ThreatIntelligenceIndicator",
]

# Category inference from KQL content
CATEGORY_MAP = {
    "SigninLogs":             "Identity & Access",
    "AuditLogs":              "Identity & Access",
    "IdentityLogonEvents":    "Identity & Access",
    "SecurityEvent":          "Endpoint Security",
    "DeviceEvents":           "Endpoint Security",
    "DeviceProcessEvents":    "Endpoint Security",
    "DeviceNetworkEvents":    "Network",
    "CommonSecurityLog":      "Network",
    "AzureActivity":          "Cloud / Azure",
    "AzureDiagnostics":       "Cloud / Azure",
    "AzureMetrics":           "Cloud / Azure",
    "OfficeActivity":         "Microsoft 365",
    "EmailEvents":            "Microsoft 365",
    "CloudAppEvents":         "Microsoft 365",
    "Syslog":                 "Linux / OS",
    "ThreatIntelligenceIndicator": "Threat Intelligence",
    "SecurityAlert":          "Alerts & Incidents",
    "SecurityIncident":       "Alerts & Incidents",
}

TAG_PATTERNS = {
    "sentinel":  ["SecurityEvent", "SigninLogs", "AuditLogs", "Workspace"],
    "defender":  ["DeviceEvents", "DeviceProcess", "DeviceNetwork", "IdentityLogon"],
    "azure":     ["AzureActivity", "AzureDiagnostics", "AzureMetrics"],
    "m365":      ["OfficeActivity", "EmailEvents", "CloudAppEvents"],
    "network":   ["CommonSecurityLog", "NetworkSession", "DeviceNetwork"],
    "identity":  ["SigninLogs", "AuditLogs", "IdentityLogon"],
    "threat-intel": ["ThreatIntelligenceIndicator"],
}


def gh_search_code(query: str, per_page: int = 30) -> list[dict]:
    """Search GitHub code index, return list of file items."""
    url = "https://api.github.com/search/code"
    params = {"q": query, "per_page": per_page}
    try:
        r = requests.get(url, headers=HEADERS, params=params, timeout=15)
        if r.status_code == 403:
            log.warning("Rate limited – sleeping 60s")
            time.sleep(60)
            return []
        r.raise_for_status()
        items = r.json().get("items", [])
        log.info(f"  '{query}' → {len(items)} results")
        return items
    except Exception as e:
        log.error(f"Search failed for '{query}': {e}")
        return []


def fetch_raw(url: str) -> str | None:
    """Download raw file content from GitHub."""
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        r.raise_for_status()
        return r.text
    except Exception as e:
        log.warning(f"Failed to fetch {url}: {e}")
        return None


def infer_category(content: str) -> str:
    for table, category in CATEGORY_MAP.items():
        if table in content:
            return category
    return "General"


def infer_tags(content: str) -> list[str]:
    tags = []
    for tag, keywords in TAG_PATTERNS.items():
        if any(kw in content for kw in keywords):
            tags.append(tag)
    return tags or ["kql"]


def extract_title(filename: str, content: str) -> str:
    """Best-effort title from filename or first comment line."""
    # Try comment lines: // Title or // Description
    for line in content.splitlines()[:5]:
        line = line.strip()
        if line.startswith("//"):
            candidate = line.lstrip("/").strip()
            if 5 < len(candidate) < 120:
                return candidate
    # Fall back to filename
    name = Path(filename).stem
    return re.sub(r"[-_]+", " ", name).title()


def extract_description(content: str) -> str:
    """Extract description from comment block at top of file."""
    lines = []
    for line in content.splitlines()[:10]:
        stripped = line.strip()
        if stripped.startswith("//"):
            text = stripped.lstrip("/").strip()
            if text:
                lines.append(text)
        elif lines:
            break
    if lines:
        return " ".join(lines[1:]) or lines[0]  # skip title line
    return "KQL query collected from public GitHub repositories."


def adapt_query(content: str, source_repo: str) -> str:
    """
    Light adaptation: ensure consistent header comment block.
    Strips existing header comments, prepends standardised block.
    """
    # Remove leading blank lines + existing comment header
    body_lines = []
    in_header = True
    for line in content.splitlines():
        if in_header and (line.strip().startswith("//") or line.strip() == ""):
            continue
        in_header = False
        body_lines.append(line)

    header = (
        f"// Source: https://github.com/{source_repo}\n"
        f"// Collected: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}\n"
        f"// KQL Hunter - https://github.com/YOUR_USER/kql-hunter\n"
    )
    return header + "\n" + "\n".join(body_lines).lstrip("\n")


def query_id(content: str, repo: str) -> str:
    return hashlib.sha1(f"{repo}:{content[:200]}".encode()).hexdigest()[:12]


def load_index() -> dict[str, dict]:
    if INDEX_FILE.exists():
        with INDEX_FILE.open() as f:
            entries = json.load(f)
        return {e["id"]: e for e in entries}
    return {}


def save_index(index: dict[str, dict]) -> None:
    QUERIES_DIR.mkdir(parents=True, exist_ok=True)
    entries = sorted(index.values(), key=lambda e: e["collected_at"], reverse=True)
    with INDEX_FILE.open("w") as f:
        json.dump(entries, f, indent=2)
    log.info(f"Saved index with {len(entries)} entries → {INDEX_FILE}")


def main():
    log.info("=== KQL Hunter starting ===")
    index = load_index()
    new_count = 0

    seen_urls: set[str] = {e.get("source_url", "") for e in index.values()}

    for search_q in SEARCH_QUERIES:
        log.info(f"Searching: {search_q}")
        items = gh_search_code(search_q)
        time.sleep(2)  # respect secondary rate limits

        for item in items:
            html_url = item.get("html_url", "")
            raw_url = item.get("url", "").replace(
                "https://api.github.com/repos", "https://raw.githubusercontent.com"
            )
            # Build proper raw URL
            raw_url = (
                f"https://raw.githubusercontent.com/"
                f"{item['repository']['full_name']}/HEAD/{item['path']}"
            )

            if html_url in seen_urls:
                continue

            content = fetch_raw(raw_url)
            if not content or len(content.strip()) < 30:
                continue

            # Skip non-KQL files that slipped through
            kql_indicators = ["| where", "| project", "| summarize", "| extend", "| join", "| distinct"]
            if not any(ind in content for ind in kql_indicators):
                continue

            repo = item["repository"]["full_name"]
            qid = query_id(content, repo)
            if qid in index:
                seen_urls.add(html_url)
                continue

            adapted = adapt_query(content, repo)

            entry = {
                "id": qid,
                "title": extract_title(item["name"], content),
                "description": extract_description(content),
                "category": infer_category(content),
                "tags": infer_tags(content),
                "content": adapted,
                "source_repo": repo,
                "source_url": html_url,
                "filename": item["name"],
                "collected_at": datetime.now(timezone.utc).isoformat(),
            }

            # Save individual .kql file
            kql_path = QUERIES_DIR / f"{qid}.kql"
            kql_path.write_text(adapted, encoding="utf-8")

            index[qid] = entry
            seen_urls.add(html_url)
            new_count += 1
            log.info(f"  + [{entry['category']}] {entry['title'][:60]}")
            time.sleep(0.5)

    save_index(index)
    log.info(f"=== Done. {new_count} new queries added. Total: {len(index)} ===")


if __name__ == "__main__":
    main()
