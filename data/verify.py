"""
data/verify.py — Pre-training integrity checker for Aegis NIDS.

What this file does:
─────────────────────────────────────────────────────────────────────────────
Before you run ml/train.py on real data, this script checks that everything
is in place and consistent. It catches mismatches early — before you waste
time on a broken training run.

Checks performed:
  1. PCAP ↔ LABEL CONSISTENCY
     Every PCAP in data/raw/ must have a matching label JSON in data/labels/.
     Every label JSON must have a matching PCAP in data/raw/.
     Missing on either side is an error.

  2. PARQUET ↔ LABEL CONSISTENCY
     Every Parquet file in data/features/ must have a matching label JSON.
     Every label JSON must have a matching Parquet file (warning, not error —
     some scenarios may not have been processed yet).

  3. LABEL FILE SCHEMA VALIDATION
     Every label JSON must have the required fields:
         scenario, attack_class, src_ip, dst_ip, pcap
     attack_class must be one of the known CLASS_NAMES.

  4. PARQUET SCHEMA VALIDATION
     Each Parquet file is opened and its columns are checked against
     FEATURE_COLUMNS from features/schema.py.
     Missing columns are reported per file.

  5. LABEL ROW COUNT REPORT
     Prints how many rows each Parquet file contains per class.
     Flags severe imbalance (any class with < 10% of the largest class).

Exit codes:
    0 — all checks passed (or only warnings)
    1 — one or more hard errors found (training would likely fail or be wrong)

Usage:
    python3 data/verify.py
    python3 data/verify.py --raw-dir data/raw --labels-dir data/labels
    python3 data/verify.py --no-pcap   # skip PCAP check (before lab is run)
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd


# ── project import — schema is the single source of truth ─────────────────
try:
    from features.schema import FEATURE_COLUMNS
except ModuleNotFoundError:
    # Allow running from inside the data/ directory
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from features.schema import FEATURE_COLUMNS

# Known valid attack classes — must match ml/train.py CLASS_NAMES
KNOWN_CLASSES: list[str] = [
    "benign",
    "ddos",
    "c2_beaconing",
    "dns_anomaly",
    "port_scan",
    "exfiltration",
]

# Required fields in every label JSON file
REQUIRED_LABEL_FIELDS: tuple[str, ...] = (
    "scenario",
    "attack_class",
    "src_ip",
    "dst_ip",
    "pcap",
)

# Imbalance threshold — warn if a class has fewer than this fraction of rows
# compared to the largest class
IMBALANCE_THRESHOLD = 0.10


# ═══════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════

class _Counters:
    """Collect errors and warnings so we can print a summary at the end."""

    def __init__(self):
        self.errors:   list[str] = []
        self.warnings: list[str] = []

    def error(self, msg: str):
        self.errors.append(msg)
        print(f"  [ERROR]   {msg}")

    def warn(self, msg: str):
        self.warnings.append(msg)
        print(f"  [WARN]    {msg}")

    def ok(self, msg: str):
        print(f"  [OK]      {msg}")

    def info(self, msg: str):
        print(f"  [INFO]    {msg}")


# ═══════════════════════════════════════════════════════════════════════════
# CHECK 1 — PCAP ↔ LABEL CONSISTENCY
# ═══════════════════════════════════════════════════════════════════════════

def check_pcap_label_consistency(
    raw_dir:    Path,
    labels_dir: Path,
    c:          _Counters,
):
    """
    Every PCAP needs a label. Every label needs a PCAP.

    PCAP file name convention: <scenario_name>.pcap
    Label file name convention: <scenario_name>.json

    The scenario name is the stem — e.g. "syn_flood".
    """
    print("\n── CHECK 1: PCAP ↔ LABEL CONSISTENCY ────────────────────────")

    pcap_stems  = {p.stem for p in raw_dir.glob("*.pcap")}   if raw_dir.exists()    else set()
    label_stems = {p.stem for p in labels_dir.glob("*.json")} if labels_dir.exists() else set()

    if not raw_dir.exists():
        c.warn(f"data/raw/ directory does not exist yet ({raw_dir}). Run the Docker lab first.")
        return

    if not pcap_stems:
        c.warn("No PCAP files found in data/raw/. Lab has not been run yet.")
        return

    # PCAPs with no label
    unlabelled = pcap_stems - label_stems
    for stem in sorted(unlabelled):
        c.error(f"PCAP '{stem}.pcap' has no matching label file in {labels_dir}.")

    # Labels with no PCAP
    missing_pcap = label_stems - pcap_stems
    for stem in sorted(missing_pcap):
        c.warn(f"Label '{stem}.json' exists but '{stem}.pcap' is missing from {raw_dir}.")

    matched = pcap_stems & label_stems
    if matched:
        c.ok(f"{len(matched)} PCAP(s) have matching label files: {sorted(matched)}")


# ═══════════════════════════════════════════════════════════════════════════
# CHECK 2 — LABEL FILE SCHEMA VALIDATION
# ═══════════════════════════════════════════════════════════════════════════

def check_label_schemas(labels_dir: Path, c: _Counters) -> dict[str, dict]:
    """
    Open every label JSON and validate its fields.
    Returns a dict of {scenario_name: label_data} for valid files.
    """
    print("\n── CHECK 2: LABEL FILE SCHEMA VALIDATION ─────────────────────")

    if not labels_dir.exists():
        c.error(f"Labels directory does not exist: {labels_dir}")
        return {}

    label_files = sorted(labels_dir.glob("*.json"))
    if not label_files:
        c.error(f"No label JSON files found in {labels_dir}.")
        return {}

    valid_labels: dict[str, dict] = {}

    for path in label_files:
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            c.error(f"{path.name}: invalid JSON — {exc}")
            continue

        # Required fields
        missing_fields = [f for f in REQUIRED_LABEL_FIELDS if f not in data]
        if missing_fields:
            c.error(f"{path.name}: missing required fields: {missing_fields}")
            continue

        # scenario name must match file stem
        if data["scenario"] != path.stem:
            c.error(
                f"{path.name}: 'scenario' field ({data['scenario']!r}) "
                f"does not match file name ({path.stem!r})."
            )
            continue

        # attack_class must be known
        if data["attack_class"] not in KNOWN_CLASSES:
            c.error(
                f"{path.name}: unknown attack_class={data['attack_class']!r}. "
                f"Known: {KNOWN_CLASSES}"
            )
            continue

        c.ok(f"{path.name}  →  attack_class={data['attack_class']}")
        valid_labels[data["scenario"]] = data

    return valid_labels


# ═══════════════════════════════════════════════════════════════════════════
# CHECK 3 — PARQUET ↔ LABEL CONSISTENCY
# ═══════════════════════════════════════════════════════════════════════════

def check_parquet_label_consistency(
    features_dir: Path,
    valid_labels:  dict[str, dict],
    c:             _Counters,
) -> list[Path]:
    """
    Every Parquet file needs a valid label.
    Returns the list of Parquet files that passed this check.
    """
    print("\n── CHECK 3: PARQUET ↔ LABEL CONSISTENCY ──────────────────────")

    if not features_dir.exists():
        c.warn(f"Features directory does not exist: {features_dir}. Run features/pipeline.py first.")
        return []

    parquet_files = sorted(features_dir.glob("*.parquet"))
    if not parquet_files:
        c.warn("No Parquet files found in data/features/. Run features/pipeline.py first.")
        return []

    parquet_stems = {p.stem for p in parquet_files}
    label_stems   = set(valid_labels.keys())

    unlabelled = parquet_stems - label_stems
    for stem in sorted(unlabelled):
        c.error(f"Parquet '{stem}.parquet' has no matching label in {valid_labels}.")

    no_parquet = label_stems - parquet_stems
    for stem in sorted(no_parquet):
        c.warn(
            f"Label '{stem}.json' exists but '{stem}.parquet' is missing. "
            f"Run: python3 features/pipeline.py --zeek-dir zeek/logs --scenario-name {stem}"
        )

    good_parquets = [p for p in parquet_files if p.stem in label_stems]
    if good_parquets:
        c.ok(f"{len(good_parquets)} Parquet file(s) have matching labels.")

    return good_parquets


# ═══════════════════════════════════════════════════════════════════════════
# CHECK 4 — PARQUET SCHEMA VALIDATION
# ═══════════════════════════════════════════════════════════════════════════

def check_parquet_schemas(parquet_files: list[Path], c: _Counters) -> list[tuple[Path, pd.DataFrame]]:
    """
    Open each Parquet file and check that FEATURE_COLUMNS are all present.
    Returns (path, dataframe) pairs for files that passed.
    """
    print("\n── CHECK 4: PARQUET SCHEMA VALIDATION ────────────────────────")

    if not parquet_files:
        c.info("No Parquet files to validate.")
        return []

    feature_set = set(FEATURE_COLUMNS)
    good: list[tuple[Path, pd.DataFrame]] = []

    for path in parquet_files:
        try:
            df = pd.read_parquet(path)
        except Exception as exc:
            c.error(f"{path.name}: could not read Parquet — {exc}")
            continue

        cols = set(df.columns)
        missing = sorted(feature_set - cols)
        extra   = sorted(cols - feature_set - {"label", "scenario", "flow_id",
                                                 "ts", "src_ip", "dst_ip", "protocol",
                                                 "uid", "cipher_suite", "ja3_hash",
                                                 "ja3s_hash", "ja4_hash"})

        if missing:
            c.error(f"{path.name}: missing FEATURE_COLUMNS: {missing}")
            continue

        if extra:
            c.info(f"{path.name}: extra columns (not a problem): {extra}")

        c.ok(f"{path.name}: {len(df)} rows, all {len(FEATURE_COLUMNS)} feature columns present.")
        good.append((path, df))

    return good


# ═══════════════════════════════════════════════════════════════════════════
# CHECK 5 — ROW COUNT AND CLASS IMBALANCE REPORT
# ═══════════════════════════════════════════════════════════════════════════

def check_class_balance(
    good_parquets: list[tuple[Path, pd.DataFrame]],
    valid_labels:  dict[str, dict],
    c:             _Counters,
):
    """
    Report row counts per class and warn about severe imbalance.

    Class imbalance is a real problem:
    - A SYN flood scenario generates thousands of flows per second
    - A C2 beacon generates one flow per minute
    - If we don't handle this, the model learns "everything is ddos"

    This check flags imbalance early so you can decide whether to:
      - Run attack scenarios for longer to generate more flows
      - Use SMOTE or sample weights in training (train.py already does this)
      - Reduce the duration of over-represented scenarios
    """
    print("\n── CHECK 5: CLASS BALANCE REPORT ─────────────────────────────")

    if not good_parquets:
        c.info("No valid Parquet files — skipping balance check.")
        return

    class_counts: dict[str, int] = {}
    for path, df in good_parquets:
        scenario    = path.stem
        label_entry = valid_labels.get(scenario, {})
        attack_class = label_entry.get("attack_class", "unknown")
        class_counts[attack_class] = class_counts.get(attack_class, 0) + len(df)

    if not class_counts:
        return

    max_count = max(class_counts.values())
    total     = sum(class_counts.values())

    print(f"\n  {'Class':<22} {'Rows':>8}  {'%':>6}  Status")
    print(f"  {'─'*22}  {'─'*8}  {'─'*6}  {'─'*10}")
    for cls in KNOWN_CLASSES:
        count = class_counts.get(cls, 0)
        pct   = count / total * 100 if total > 0 else 0
        ratio = count / max_count if max_count > 0 else 0
        if count == 0:
            status = "MISSING"
            c.warn(f"Class '{cls}' has 0 rows. No training data for this class.")
        elif ratio < IMBALANCE_THRESHOLD:
            status = f"IMBALANCED ({ratio:.1%} of majority)"
            c.warn(
                f"Class '{cls}' has only {count} rows ({ratio:.1%} of "
                f"'{max(class_counts, key=class_counts.get)}' with {max_count} rows). "
                f"Consider running this scenario longer or using SMOTE."
            )
        else:
            status = "OK"
        print(f"  {cls:<22} {count:>8}  {pct:>5.1f}%  {status}")

    print(f"\n  Total rows: {total}")


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main(
    raw_dir:      Path = Path("data/raw"),
    labels_dir:   Path = Path("data/labels"),
    features_dir: Path = Path("data/features"),
    skip_pcap:    bool = False,
) -> int:
    """
    Run all checks. Returns 0 if clean, 1 if any errors found.
    """
    c = _Counters()

    print("═" * 60)
    print("AEGIS NIDS — DATA INTEGRITY VERIFICATION")
    print("═" * 60)

    # Check 1: PCAP ↔ label (optional — skip before lab is run)
    if not skip_pcap:
        check_pcap_label_consistency(raw_dir, labels_dir, c)
    else:
        print("\n── CHECK 1: PCAP check skipped (--no-pcap) ───────────────────")

    # Check 2: label schema
    valid_labels = check_label_schemas(labels_dir, c)

    # Check 3: parquet ↔ label
    good_parquets_paths = check_parquet_label_consistency(features_dir, valid_labels, c)

    # Check 4: parquet schema
    good_parquets = check_parquet_schemas(good_parquets_paths, c)

    # Check 5: class balance
    check_class_balance(good_parquets, valid_labels, c)

    # ── Summary ───────────────────────────────────────────────────────────
    print("\n" + "═" * 60)
    print("SUMMARY")
    print("═" * 60)

    if c.errors:
        print(f"\n  ERRORS   ({len(c.errors)}):")
        for msg in c.errors:
            print(f"    ✗ {msg}")

    if c.warnings:
        print(f"\n  WARNINGS ({len(c.warnings)}):")
        for msg in c.warnings:
            print(f"    ⚠ {msg}")

    if not c.errors and not c.warnings:
        print("\n  All checks passed. Ready to train.")
    elif not c.errors:
        print(f"\n  {len(c.warnings)} warning(s), no errors. Training should work.")
    else:
        print(
            f"\n  {len(c.errors)} error(s) found. Fix these before running ml/train.py."
        )

    print()
    return 1 if c.errors else 0


# ── CLI ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Verify Aegis NIDS data integrity before training."
    )
    parser.add_argument(
        "--raw-dir",
        type=Path,
        default=Path("data/raw"),
        help="Directory containing PCAP files (default: data/raw)",
    )
    parser.add_argument(
        "--labels-dir",
        type=Path,
        default=Path("data/labels"),
        help="Directory containing label JSON files (default: data/labels)",
    )
    parser.add_argument(
        "--features-dir",
        type=Path,
        default=Path("data/features"),
        help="Directory containing Parquet files (default: data/features)",
    )
    parser.add_argument(
        "--no-pcap",
        action="store_true",
        help="Skip the PCAP presence check (useful before the Docker lab has been run)",
    )
    args = parser.parse_args()

    sys.exit(
        main(
            raw_dir      = args.raw_dir,
            labels_dir   = args.labels_dir,
            features_dir = args.features_dir,
            skip_pcap    = args.no_pcap,
        )
    )
