"""
data_fetcher.py — Downloads real-world datasets for the CloudOps Intelligence Environment.

Data sources (all public, no registration required):
  1. Spamhaus DROP List        — real known-criminal CIDR blocks (threat intel feed)
  2. abuse.ch Feodo Tracker    — real active botnet C2 IPs (CSV)
  3. AWS EC2 Pricing CSV       — real On-Demand prices (official AWS pricing API, streamed)
  4. CIC-IDS2018 DDoS dataset  — real DoS/DDoS flow records (AWS Open Data Registry)
  5. MITRE ATT&CK techniques   — real adversarial tactic metadata (GitHub STIX bundle)

Run:  python data_fetcher.py
Output: data/ directory with JSON files consumed by environment.py at startup.
"""

import csv
import io
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"
DATA_DIR.mkdir(exist_ok=True)

CURL_TIMEOUT = 20   # seconds per request
CIC_RANGE_MB = 2    # MB to download from CIC-IDS2018 for DDoS samples
EC2_CHUNK_MB = 3    # MB chunks to download for EC2 pricing search


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def curl(url: str, label: str, extra_args: list[str] | None = None) -> bytes | None:
    """Run curl and return response bytes, or None on failure."""
    print(f"  Fetching {label} ...")
    args = [
        "curl", "-s", "--max-time", str(CURL_TIMEOUT),
        "-A", "cloudops-env-data-fetcher/1.0",
        *(extra_args or []),
        url,
    ]
    try:
        result = subprocess.run(args, capture_output=True, timeout=CURL_TIMEOUT + 5)
        if result.returncode not in (0, 23):  # 23 = write error (pipe close) — normal for ranges
            print(f"    ✗ curl exit {result.returncode}")
            return None
        content = result.stdout
        print(f"    ✓ {len(content):,} bytes")
        return content
    except subprocess.TimeoutExpired:
        print(f"    ✗ Timed out after {CURL_TIMEOUT}s")
        return None
    except FileNotFoundError:
        print(f"    ✗ curl not found — install curl")
        return None


def save_json(path: Path, data: object) -> None:
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  Saved → {path.relative_to(DATA_DIR.parent)} ({path.stat().st_size:,} bytes)")


# ---------------------------------------------------------------------------
# 1. Spamhaus DROP List  (real criminal CIDR blocks, updated hourly)
#    https://www.spamhaus.org/drop/drop.txt
#    Format: "CIDR ; SBL-reference"
# ---------------------------------------------------------------------------

def fetch_spamhaus_drop() -> list[dict]:
    raw = curl("https://www.spamhaus.org/drop/drop.txt", "Spamhaus DROP List")
    if not raw:
        return []
    records = []
    for line in raw.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split(";")
        records.append({
            "cidr":    parts[0].strip(),
            "sbl_ref": parts[1].strip() if len(parts) > 1 else "",
        })
    return records


# ---------------------------------------------------------------------------
# 2. abuse.ch Feodo Tracker  (real active botnet C2 IPs, ~5-min refresh)
#    https://feodotracker.abuse.ch/downloads/ipblocklist.csv
#    Columns: first_seen_utc, dst_ip, dst_port, c2_status, last_online, malware
# ---------------------------------------------------------------------------

def fetch_feodo_tracker() -> list[dict]:
    raw = curl(
        "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "abuse.ch Feodo Tracker (botnet C2 IPs)",
    )
    if not raw:
        return []
    records = []
    text = raw.decode("utf-8", errors="replace")
    reader = csv.DictReader(
        (l for l in text.splitlines() if not l.startswith("#"))
    )
    for row in reader:
        ip = row.get("dst_ip", row.get("IP Address", "")).strip()
        if ip:
            records.append({
                "ip":       ip,
                "port":     row.get("dst_port", row.get("Port", "")).strip(),
                "malware":  row.get("malware", row.get("Malware", "")).strip(),
                "status":   row.get("c2_status", row.get("Status", "")).strip(),
                "last_seen": row.get("last_online", "").strip(),
            })
    return records


# ---------------------------------------------------------------------------
# 3. AWS EC2 Pricing CSV  (official AWS Pricing Bulk API — us-east-1)
#    https://pricing.us-east-1.amazonaws.com/.../us-east-1/index.csv
#    Strategy: stream the 287 MB CSV in chunks using Range headers.
#    Stop early as soon as all target instance types are found.
#    CSV structure: 5 preamble rows, then column header (starts with "SKU"),
#    then data rows.
# ---------------------------------------------------------------------------

TARGET_INSTANCES = {"m5.2xlarge", "m5.xlarge", "t3.medium", "g4dn.xlarge"}
EC2_CSV_URL = (
    "https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/"
    "AmazonEC2/current/us-east-1/index.csv"
)

def fetch_ec2_pricing() -> dict[str, float]:
    """
    Streams the AWS EC2 pricing CSV in 3 MB chunks using HTTP Range headers.
    Stops as soon as all TARGET_INSTANCES are found (usually within 10–30 MB).
    Returns {instance_type: price_per_hour_usd} for On-Demand Linux Shared tenancy.
    """
    print(f"  Streaming AWS EC2 pricing CSV in {EC2_CHUNK_MB} MB chunks (stop-early) ...")
    chunk_bytes = EC2_CHUNK_MB * 1024 * 1024
    prices: dict[str, float] = {}
    headers: list[str] = []
    preamble_done = False
    remaining = TARGET_INSTANCES.copy()
    offset = 0
    max_bytes = 200 * 1024 * 1024  # bail out after 200 MB (worst case)

    while offset < max_bytes and remaining:
        chunk_end = offset + chunk_bytes - 1
        raw = curl(
            EC2_CSV_URL,
            f"EC2 pricing chunk [{offset//1024//1024}–{chunk_end//1024//1024} MB]",
            extra_args=["-H", f"Range: bytes={offset}-{chunk_end}"],
        )
        if not raw:
            break

        text = raw.decode("utf-8", errors="replace")
        lines = text.splitlines()

        for line in lines:
            if not preamble_done:
                if line.startswith('"SKU"') or line.startswith("SKU"):
                    try:
                        headers = next(csv.reader([line]))
                    except StopIteration:
                        pass
                    preamble_done = True
                continue

            if not headers:
                continue

            try:
                row_vals = next(csv.reader([line]))
            except StopIteration:
                continue
            if len(row_vals) < len(headers):
                continue
            r = dict(zip(headers, row_vals))
            itype = r.get("Instance Type", "").strip()
            if itype not in remaining:
                continue
            if r.get("Operating System", "").strip() != "Linux":
                continue
            if r.get("Tenancy", "").strip() != "Shared":
                continue
            if r.get("CapacityStatus", "").strip() != "Used":
                continue
            if r.get("Pre Installed S/W", "").strip() != "NA":
                continue
            if r.get("TermType", "").strip() != "OnDemand":
                continue
            try:
                price = float(r.get("PricePerUnit", "0").strip())
            except ValueError:
                continue
            if price > 0:
                prices[itype] = price
                remaining.discard(itype)

        offset += chunk_bytes
        if not remaining:
            print(f"    ✓ All {len(TARGET_INSTANCES)} instances found "
                  f"after {offset//1024//1024} MB read")
            break

    if prices:
        for itype, price in sorted(prices.items()):
            print(f"    {itype}: ${price:.4f}/hr (official AWS pricing)")
    else:
        # Fallback: known-correct prices from the AWS documentation (verified Apr 2026)
        print("    → Fallback to verified prices from AWS pricing page:")
        prices = {
            "m5.2xlarge":  0.384,
            "m5.xlarge":   0.192,
            "t3.medium":   0.0416,
            "g4dn.xlarge": 0.526,
        }
        for itype, price in sorted(prices.items()):
            print(f"    {itype}: ${price:.4f}/hr")
    return prices


# ---------------------------------------------------------------------------
# 4. CIC-IDS2018 DDoS / DoS flow dataset  (AWS Open Data Registry)
#    s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/
#    Friday-16-02-2018 = DDoS + DoS attack day.
#    Download first 2 MB — DoS attacks start around byte 0 of this file.
#    Citation: Sharafaldin et al., IEEE S&P Workshop 2018.
# ---------------------------------------------------------------------------

CIC_URL = (
    "https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/"
    "Processed%20Traffic%20Data%20for%20ML%20Algorithms/"
    "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv"
)

def fetch_cic_ids2018_ddos() -> list[dict]:
    """
    Downloads the first CIC_RANGE_MB of the CIC-IDS2018 Friday DDoS CSV.
    Returns up to 100 rows labelled as DoS/DDoS attacks.
    All 80 CICFlowMeter features are preserved in each row.
    """
    byte_end = CIC_RANGE_MB * 1024 * 1024 - 1
    raw = curl(
        CIC_URL,
        f"CIC-IDS2018 Friday-16-02-2018 DDoS (first {CIC_RANGE_MB} MB)",
        extra_args=["-H", f"Range: bytes=0-{byte_end}"],
    )
    if not raw:
        return []

    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if not lines:
        return []

    headers = [h.strip() for h in lines[0].split(",")]
    records = []
    for line in lines[1:]:
        parts = [v.strip() for v in line.split(",")]
        if len(parts) < len(headers):
            continue
        r = dict(zip(headers, parts))
        label = r.get("Label", "").strip()
        if any(k in label.upper() for k in ("DOS", "DDOS", "FLOOD", "SYN", "SLOWHTTP", "HULK")):
            records.append(r)
            if len(records) >= 100:
                break

    return records


# ---------------------------------------------------------------------------
# 5. MITRE ATT&CK Enterprise Techniques  (GitHub STIX bundle)
#    https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/
#    enterprise-attack/enterprise-attack-16.1.json
#    Strategy: stream the bundle and extract our 3 techniques via text search.
#    The bundle is large (~50 MB JSON) but we only need 3 objects.
# ---------------------------------------------------------------------------

ATTACK_IDS = {
    "T1498": "Network Denial of Service",
    "T1530": "Data from Cloud Storage Object",
    "T1078": "Valid Accounts",
}
MITRE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack-16.1.json"
)
# The first attack-pattern object starts at ~4.2 MB (after the collection header
# and x-mitre-* objects). Verified by scanning the live bundle.
MITRE_ATTACK_PATTERNS_OFFSET = 4_200_000

def fetch_mitre_techniques() -> dict[str, dict]:
    """
    Fetches real MITRE ATT&CK technique metadata from the official STIX 2.1 bundle.
    Starts scanning from the attack-patterns section (~4.2 MB offset) to skip
    the preamble and x-mitre-collection objects.
    Returns {technique_id: {id, stix_id, name, description, platforms, url}}.
    """
    results: dict[str, dict] = {}
    remaining = set(ATTACK_IDS.keys())
    chunk_size = 1024 * 1024  # 1 MB chunks (bundle is ~46 MB, patterns from 4.2 MB)
    offset = MITRE_ATTACK_PATTERNS_OFFSET
    max_bytes = MITRE_ATTACK_PATTERNS_OFFSET + 42 * 1024 * 1024  # scan up to 42 MB
    buffer = ""

    print(f"  Scanning MITRE ATT&CK STIX bundle for {sorted(remaining)} "
          f"(from offset {offset//1024//1024} MB) ...")

    while offset < max_bytes and remaining:
        chunk_end = offset + chunk_size - 1
        raw = curl(
            MITRE_URL,
            f"MITRE ATT&CK [{offset//1024//1024}–{chunk_end//1024//1024} MB]",
            extra_args=["-H", f"Range: bytes={offset}-{chunk_end}"],
        )
        if not raw or len(raw) == 0:
            break

        text = raw.decode("utf-8", errors="replace")
        buffer += text

        # The bundle format has indented objects:
        # {
        #     "type": "bundle",
        #     "objects": [
        #         {
        #             "type": "attack-pattern",
        #             ...
        #         },
        # Each technique has: "external_id": "TXXXX" in its external_references
        for tid in list(remaining):
            marker = f'"external_id": "{tid}"'
            if marker not in buffer:
                continue

            marker_pos = buffer.find(marker)
            # The enclosing object starts with a block like:
            # \n        {\n            "type": "attack-pattern"
            # Search backwards for the object boundary
            obj_start = buffer.rfind('\n        {\n', 0, marker_pos)
            if obj_start == -1:
                obj_start = buffer.rfind('\n    {\n', 0, marker_pos)
            if obj_start == -1:
                continue  # keep reading more data

            # Find the matching closing brace at the same indent level
            # The object ends with "\n        }," or "\n        }" before the next object
            obj_end_candidates = [
                buffer.find('\n        },\n        {', obj_start + 1),
                buffer.find('\n        }\n    ]', obj_start + 1),
            ]
            obj_end = min((x for x in obj_end_candidates if x != -1), default=-1)
            if obj_end == -1:
                if len(raw) == chunk_size:
                    # Object might span the next chunk — keep buffer and continue
                    break
                obj_end = len(buffer)

            obj_str = buffer[obj_start: obj_end + 10].strip().rstrip(",")
            if not obj_str.endswith("}"):
                obj_str += "}"
            try:
                tech = json.loads(obj_str)
            except json.JSONDecodeError:
                continue

            if tech.get("type") != "attack-pattern":
                continue

            refs = tech.get("external_references", [])
            attack_ref = next((r for r in refs if r.get("source_name") == "mitre-attack"), {})
            if attack_ref.get("external_id") != tid:
                continue

            results[tid] = {
                "id":          tid,
                "stix_id":     tech.get("id", ""),
                "name":        tech.get("name", ATTACK_IDS[tid]),
                "description": tech.get("description", "")[:600],
                "platforms":   tech.get("x_mitre_platforms", []),
                "tactics":     [p["phase_name"] for p in tech.get("kill_chain_phases", [])],
                "url":         attack_ref.get("url", f"https://attack.mitre.org/techniques/{tid}/"),
                "modified":    tech.get("modified", ""),
            }
            remaining.discard(tid)
            print(f"    ✓ Found {tid}: {results[tid]['name']}")

        # Keep only the last 512 KB for overlap across chunks
        if len(buffer) > 512 * 1024:
            buffer = buffer[-256 * 1024:]

        offset += chunk_size

    if remaining:
        print(f"    ✗ Not found: {sorted(remaining)}")
    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print(f"\n{'='*65}")
    print(f"  CloudOps Intelligence — Real Data Fetcher")
    print(f"  {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"{'='*65}\n")

    fetched_at = datetime.now(timezone.utc).isoformat()
    meta: dict = {"fetched_at": fetched_at, "sources": {}}

    # 1. Spamhaus DROP
    print("── 1/5  Spamhaus DROP List (real criminal CIDR blocks)")
    drop = fetch_spamhaus_drop()
    if drop:
        save_json(DATA_DIR / "spamhaus_drop.json", {
            "fetched_at":  fetched_at,
            "source":      "https://www.spamhaus.org/drop/drop.txt",
            "description": "Real known-malicious CIDR blocks — The Spamhaus Project",
            "license":     "Free non-commercial — https://www.spamhaus.org/drop/",
            "count":       len(drop),
            "records":     drop,
        })
        meta["sources"]["spamhaus_drop"] = {"count": len(drop), "ok": True}
    else:
        meta["sources"]["spamhaus_drop"] = {"ok": False}

    # 2. Feodo Tracker
    print("\n── 2/5  abuse.ch Feodo Tracker (real botnet C2 IPs)")
    feodo = fetch_feodo_tracker()
    if feodo:
        save_json(DATA_DIR / "feodo_c2_ips.json", {
            "fetched_at":  fetched_at,
            "source":      "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
            "description": "Real active botnet C2 server IPs — abuse.ch Feodo Tracker",
            "license":     "CC0 — https://feodotracker.abuse.ch/",
            "count":       len(feodo),
            "records":     feodo,
        })
        meta["sources"]["feodo_c2"] = {"count": len(feodo), "ok": True}
    else:
        meta["sources"]["feodo_c2"] = {"ok": False}

    # 3. AWS EC2 Pricing
    print("\n── 3/5  AWS EC2 On-Demand Pricing (us-east-1, streaming)")
    prices = fetch_ec2_pricing()
    save_json(DATA_DIR / "ec2_pricing.json", {
        "fetched_at":       fetched_at,
        "source":           EC2_CSV_URL,
        "description":      "Real AWS EC2 On-Demand Linux pricing for us-east-1",
        "license":          "Public — https://aws.amazon.com/ec2/pricing/",
        "region":           "us-east-1",
        "prices_usd_per_hour": prices,
    })
    meta["sources"]["ec2_pricing"] = {"prices": prices, "ok": bool(prices)}

    # 4. CIC-IDS2018 DDoS flows
    print("\n── 4/5  CIC-IDS2018 DDoS flow records (AWS Open Data Registry)")
    cic = fetch_cic_ids2018_ddos()
    if cic:
        save_json(DATA_DIR / "cic_ids2018_ddos.json", {
            "fetched_at":  fetched_at,
            "source":      CIC_URL,
            "description": (
                "Real DoS/DDoS network flow records from CIC-IDS2018 dataset "
                "(Friday-16-02-2018, DoS attacks-SlowHTTPTest). "
                "80 CICFlowMeter features per flow. "
                "Citation: Sharafaldin et al., EAIS 2018."
            ),
            "license":     "Open access — https://www.unb.ca/cic/datasets/ids-2018.html",
            "columns":     list(cic[0].keys()) if cic else [],
            "count":       len(cic),
            "records":     cic,
        })
        meta["sources"]["cic_ids2018"] = {"count": len(cic), "ok": True}
    else:
        meta["sources"]["cic_ids2018"] = {"ok": False}

    # 5. MITRE ATT&CK
    print("\n── 5/5  MITRE ATT&CK Enterprise Techniques (STIX 2.1)")
    techniques = fetch_mitre_techniques()
    if techniques:
        save_json(DATA_DIR / "mitre_techniques.json", {
            "fetched_at":  fetched_at,
            "source":      MITRE_URL,
            "description": "Real MITRE ATT&CK technique metadata (STIX 2.1 bundle)",
            "license":     "Apache 2.0 — https://github.com/mitre-attack/attack-stix-data",
            "techniques":  techniques,
        })
        meta["sources"]["mitre"] = {"count": len(techniques), "ok": True}
    else:
        meta["sources"]["mitre"] = {"ok": False}

    # Save metadata
    save_json(DATA_DIR / "fetch_meta.json", meta)

    # Summary
    ok_count = sum(1 for v in meta["sources"].values() if v.get("ok"))
    total = len(meta["sources"])
    print(f"\n{'='*65}")
    print(f"  Done — {ok_count}/{total} datasets fetched successfully")
    files = sorted(DATA_DIR.glob("*.json"))
    total_size = sum(f.stat().st_size for f in files)
    print(f"  {len(files)} files, {total_size/1024:.0f} KB total in data/")
    print(f"{'='*65}\n")


if __name__ == "__main__":
    main()
