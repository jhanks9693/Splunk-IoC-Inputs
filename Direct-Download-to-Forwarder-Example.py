#!/usr/bin/env python3
"""
Simple threat feed downloader for Splunk forwarder.

- Downloads a feed via HTTP/HTTPS (no Splunk API).
- Performs basic validation (status code, non-empty, minimal columns).
- Normalizes into one event per IOC with fields:
  indicator, type, source, first_seen, last_seen
- Writes to a fixed path for Splunk UF to monitor.

Run on a schedule (cron / Task Scheduler).
"""

import csv
import datetime
import os
import sys
from typing import List, Dict, Optional

import requests

# ------------- CONFIGURATION -------------

FEED_URL = "https://example.com/path/to/threatfeed.csv"  # <-- change this
SOURCE_NAME = "example_feed"                             # tag your source
OUTPUT_PATH = "/opt/splunkforwarder/var/threatfeeds/feed_example.log"  # Linux UF path
# For Windows UF, something like:
# OUTPUT_PATH = r"C:\Program Files\SplunkUniversalForwarder\var\threatfeeds\feed_example.log"

TIMEOUT_SECONDS = 30
MIN_LINES_REQUIRED = 5        # basic sanity check
VERIFY_TLS = True             # set False only if you absolutely must

# If your feed is not CSV, adjust parse_feed() accordingly
# Example expected header: indicator,type,first_seen,last_seen
EXPECTED_COLUMNS = ["indicator"]  # we require at least this column


# ------------- LOGGING HELPERS -------------

def log(msg: str) -> None:
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    print(f"{ts} [INFO] {msg}")


def log_error(msg: str) -> None:
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    print(f"{ts} [ERROR] {msg}", file=sys.stderr)


# ------------- FETCH & VALIDATION -------------

def fetch_feed(url: str) -> str:
    """Fetch the raw feed body as text."""
    log(f"Downloading feed from {url}")
    resp = requests.get(url, timeout=TIMEOUT_SECONDS, verify=VERIFY_TLS)
    if resp.status_code != 200:
        raise RuntimeError(f"HTTP {resp.status_code} from feed URL")
    text = resp.text
    if not text or not text.strip():
        raise RuntimeError("Feed body is empty")
    return text


def basic_text_sanity_check(text: str) -> None:
    """Very basic sanity checks before parsing."""
    lines = [l for l in text.splitlines() if l.strip()]
    if len(lines) < MIN_LINES_REQUIRED:
        raise RuntimeError(
            f"Feed too small: only {len(lines)} non-empty lines (min {MIN_LINES_REQUIRED})"
        )


# ------------- PARSING & NORMALIZATION -------------

def parse_feed_csv(text: str) -> List[Dict[str, str]]:
    """
    Parse CSV feed into list of dicts.

    If the feed has a header row, DictReader will use it.
    If no header, treat whole line as 'indicator'.
    """
    lines = [l for l in text.splitlines() if l.strip()]
    if not lines:
        return []

    # Try to detect a header by checking for comma and known column
    first_line = lines[0]
    has_comma = "," in first_line

    records: List[Dict[str, str]] = []

    if has_comma:
        # Attempt CSV with header
        reader = csv.DictReader(lines)
        fieldnames = [f.strip() for f in (reader.fieldnames or [])]

        # Require at least one expected column if we think we have a header
        if EXPECTED_COLUMNS and not any(c in fieldnames for c in EXPECTED_COLUMNS):
            log("CSV header does not contain expected columns; "
                "falling back to 'indicator'-only parsing")
            # fall through to simple one-field mode
        else:
            for row in reader:
                # Normalize keys and strip whitespace
                rec = {k.strip(): (v or "").strip() for k, v in row.items()}
                records.append(rec)
            return records

    # Fallback: treat each non-empty line as a simple indicator
    for line in lines:
        indicator = line.strip()
        if not indicator or indicator.startswith("#"):
            continue
        records.append({"indicator": indicator})

    return records


def normalize_records(raw_records: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """
    Normalize raw feed records to:
    indicator, type, source, first_seen, last_seen
    """
    normalized: List[Dict[str, str]] = []
    now = datetime.datetime.utcnow().isoformat() + "Z"

    for r in raw_records:
        indicator = r.get("indicator") or r.get("value") or r.get("ioc")
        if not indicator:
            # Try common alt headers
            for key in ("ip", "ip_address", "domain", "url", "hash"):
                if r.get(key):
                    indicator = r[key]
                    break
        if not indicator:
            continue  # skip unusable row

        # Basic type inference if not provided
        ioc_type = r.get("type") or infer_indicator_type(indicator)

        first_seen = r.get("first_seen") or r.get("firstSeen") or now
        last_seen = r.get("last_seen") or r.get("lastSeen") or now

        normalized.append(
            {
                "indicator": indicator,
                "type": ioc_type,
                "source": SOURCE_NAME,
                "first_seen": first_seen,
                "last_seen": last_seen,
            }
        )

    return normalized


def infer_indicator_type(indicator: str) -> str:
    """Very simple heuristic for IOC type."""
    # Not perfect; tune as needed
    indicator = indicator.strip()
    if ":" in indicator and indicator.split(":", 1)[0] in ("http", "https"):
        return "url"
    if "." in indicator and not any(c in indicator for c in "/:@"):
        # Could be IP or domain
        parts = indicator.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return "ip"
        return "domain"
    if len(indicator) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in indicator):
        return "hash"
    return "unknown"


# ------------- OUTPUT -------------

def write_output(path: str, records: List[Dict[str, str]]) -> None:
    """
    Write records as one line per event, pipe-delimited key=value pairs.

    Example line:
    indicator=1.2.3.4 type=ip source=example_feed first_seen=... last_seen=...
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)

    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        for rec in records:
            line = " ".join(f"{k}={escape_value(v)}" for k, v in rec.items())
            f.write(line + "\n")

    # Atomic replace
    os.replace(tmp_path, path)
    log(f"Wrote {len(records)} records to {path}")


def escape_value(v: Optional[str]) -> str:
    if v is None:
        return ""
    # Simple escaping: wrap spaces in quotes
    s = str(v)
    if " " in s:
        return f"\"{s}\""
    return s


# ------------- MAIN -------------

def main() -> int:
    try:
        raw_text = fetch_feed(FEED_URL)
        basic_text_sanity_check(raw_text)
        raw_records = parse_feed_csv(raw_text)
        if not raw_records:
            raise RuntimeError("No records parsed from feed")
        normalized = normalize_records(raw_records)
        if not normalized:
            raise RuntimeError("No usable indicators after normalization")
        write_output(OUTPUT_PATH, normalized)
        log("Feed processing completed successfully")
        return 0
    except Exception as e:
        log_error(f"Feed processing failed: {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

