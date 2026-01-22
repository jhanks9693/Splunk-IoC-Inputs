#!/usr/bin/env python3
import json
import socket
import requests
from datetime import datetime, timedelta, timezone

# ====== CONFIGURE THESE ======
OTX_API_KEY = "c96675e91e953bc5b79273f642c1f4542c10f0793ba5cfc5a9b6ffde4d409a55"
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"  # OTX v1 external API base [web:2]

# Splunk HEC configuration
SPLUNK_HEC_URL = "https://192.168.64.1:8088/services/collector/event"  # adjust host as needed
SPLUNK_HEC_TOKEN = "01af8ecd-ff1b-4c44-a3fc-611bf657fc1b"
# Set index/sourcetype on the HEC token in Splunk Web. [web:13][web:119]

# Polling window
LOOKBACK_MINUTES = 65

# TLS for OTX
VERIFY_SSL_OTX = True

# OTX request behavior
MAX_OTX_RETRIES = 3
OTX_TIMEOUT = 60  # seconds

# =============================


def check_dns():
    """Quick DNS sanity check so failures are clearer."""
    try:
        socket.getaddrinfo("otx.alienvault.com", 443)
    except socket.gaierror as e:
        raise SystemExit(
            f"DNS lookup for otx.alienvault.com failed: {e}. "
            "Fix DNS/network on this host, then re-run."
        )


def iso_to_epoch(ts: str) -> float:
    """
    Convert ISO8601 or epoch-like string to Unix epoch seconds (float). [web:119]
    """
    if not ts:
        return datetime.now(timezone.utc).timestamp()

    # If it's already numeric (e.g. "1705250000.123"), just cast.
    if ts.replace(".", "", 1).isdigit():
        return float(ts)

    # Handle common OTX ISO8601 forms, including trailing Z.
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return dt.timestamp()


def get_otx_activity(since_timestamp_iso):
    """
    Pull subscribed pulses from OTX, stopping when results are older than our lookback. [web:2][web:42]
    """
    base_url = f"{OTX_BASE_URL}/pulses/subscribed"
    headers = {
        "X-OTX-API-KEY": OTX_API_KEY,
        "Content-Type": "application/json",
        "User-Agent": "splunk-otx-forwarder/1.4",
    }

    url = base_url
    params = {"limit": 20, "page": 1}  # smaller page size
    first = True

    all_pulses = []

    while True:
        for attempt in range(1, MAX_OTX_RETRIES + 1):
            try:
                if first:
                    resp = requests.get(
                        url,
                        headers=headers,
                        params=params,
                        timeout=OTX_TIMEOUT,
                        verify=VERIFY_SSL_OTX,
                    )
                else:
                    resp = requests.get(
                        url,
                        headers=headers,
                        timeout=OTX_TIMEOUT,
                        verify=VERIFY_SSL_OTX,
                    )
                break
            except requests.exceptions.ReadTimeout as e:
                if attempt == MAX_OTX_RETRIES:
                    raise SystemExit(
                        f"OTX request timed out after {MAX_OTX_RETRIES} attempts: {e}"
                    )
                continue

        if resp.status_code != 200:
            raise SystemExit(
                f"OTX HTTP {resp.status_code} for {resp.url}:\n{resp.text}"
            )

        data = resp.json()
        results = data.get("results", [])
        if not results:
            break

        all_old = True

        for pulse in results:
            modified = pulse.get("modified") or pulse.get("created") or ""
            if modified >= since_timestamp_iso:
                all_pulses.append(pulse)
                all_old = False

        # If everything on this page is older than our since, stop paging.
        if all_old:
            break

        next_page = data.get("next")
        if not next_page:
            break

        url = next_page
        first = False

    return all_pulses


def build_splunk_events_from_pulse(pulse):
    """
    Build plain HEC events with epoch 'time'; index/sourcetype come from HEC token. [web:116][web:119]
    """
    events = []

    modified = pulse.get("modified")
    created = pulse.get("created")

    base_dt = (
        datetime.fromisoformat(modified.replace("Z", "+00:00")) if modified else
        datetime.fromisoformat(created.replace("Z", "+00:00")) if created else
        datetime.now(timezone.utc)
    )
    base_epoch = base_dt.timestamp()

    pulse_id = pulse.get("id")
    pulse_name = pulse.get("name")
    pulse_description = pulse.get("description")
    tags = pulse.get("tags", [])
    references = pulse.get("references", [])
    adversary = pulse.get("adversary")
    tlp = pulse.get("tlp")
    author_name = (pulse.get("creator") or {}).get("username")

    # Pulse-level event
    pulse_event = {
        "time": base_epoch,
        "event": {
            "event_type": "otx_pulse",
            "pulse_id": pulse_id,
            "name": pulse_name,
            "description": pulse_description,
            "tags": tags,
            "references": references,
            "adversary": adversary,
            "tlp": tlp,
            "author": author_name,
            "modified": modified,
            "created": created,
        },
    }
    events.append(pulse_event)

    # Indicator-level events
    for indicator in pulse.get("indicators", []):
        ind_created = indicator.get("created")
        if ind_created:
            ind_dt = datetime.fromisoformat(ind_created.replace("Z", "+00:00"))
            ind_time = ind_dt.timestamp()
        else:
            ind_time = base_epoch

        ind_event = {
            "time": ind_time,
            "event": {
                "event_type": "otx_indicator",
                "pulse_id": pulse_id,
                "pulse_name": pulse_name,
                "indicator": indicator.get("indicator"),
                "indicator_type": indicator.get("type"),
                "title": indicator.get("title"),
                "description": indicator.get("description"),
                "content": indicator.get("content"),
                "tags": tags,
                "tlp": tlp,
                "author": author_name,
                "created": ind_created,
                "expiration": indicator.get("expiration"),
                "is_active": indicator.get("is_active"),
            },
        }
        events.append(ind_event)

    return events


def send_to_splunk(events):
    """
    Send events as newline-delimited JSON to HEC.
    Index and sourcetype come from the HEC token configuration. [web:13][web:119]
    """
    if not events:
        return

    headers = {
        "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
        "Content-Type": "application/json",
    }

    payload_lines = [json.dumps(e, separators=(",", ":")) for e in events]
    payload = "\n".join(payload_lines)

    resp = requests.post(
        SPLUNK_HEC_URL,
        headers=headers,
        data=payload,
        verify=False,  # lab/self-signed HEC
        timeout=30,
    )
    if resp.status_code not in (200, 201):
        raise SystemExit(f"HEC HTTP {resp.status_code}: {resp.text}")


def main():
    check_dns()

    now = datetime.now(timezone.utc)
    since = now - timedelta(minutes=LOOKBACK_MINUTES)
    since_iso = since.isoformat()

    pulses = get_otx_activity(since_iso)
    all_events = []
    for p in pulses:
        all_events.extend(build_splunk_events_from_pulse(p))

    send_to_splunk(all_events)


if __name__ == "__main__":
    main()

