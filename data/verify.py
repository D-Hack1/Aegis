"""Validate durable feature Parquet files before model-training handoff."""

import argparse
import glob
import math
import sys
from collections import Counter
from dataclasses import dataclass, field
from numbers import Real
from pathlib import Path

import pandas as pd

# Support direct execution with `python data/verify.py ...` from the repository root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from features.pipeline import BOOL_SCHEMA_FIELDS, INT_SCHEMA_FIELDS, SCHEMA_COLUMNS
from features.schema import FEATURE_COLUMNS, FeatureRow


# Copied exactly from the documented FeatureRow.label durable training-label contract.
DURABLE_LABEL_VALUES = {
    "ddos",
    "c2_beaconing",
    "dns_anomaly",
    "malware_tls",
    "port_scan",
    "exfiltration",
    "benign",
}

MODEL_ONLY_COLUMNS = frozenset(FEATURE_COLUMNS) - frozenset(SCHEMA_COLUMNS)
NUMERIC_SCHEMA_FIELDS = tuple(
    name
    for name, schema_field in FeatureRow.__dataclass_fields__.items()
    if schema_field.type in (int, float)
)
NON_NEGATIVE_FIELDS = frozenset(NUMERIC_SCHEMA_FIELDS) - {"ts", "src_port", "dst_port"}


@dataclass
class ValidationResult:
    path: Path
    row_count: int = 0
    column_count: int = 0
    label_counts: Counter = field(default_factory=Counter)
    checks: dict[str, bool] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def passed(self):
        return not self.errors

    def fail(self, check, message):
        self.checks[check] = False
        self.errors.append(message)


def _missing(value):
    return value is None or (not isinstance(value, (list, tuple, dict, set)) and pd.isna(value))


def _blank(value):
    return _missing(value) or not str(value).strip()


def _boolean_value(value):
    if isinstance(value, bool):
        return True
    return isinstance(value, Real) and not isinstance(value, bool) and value in (0, 1)


def _validate_schema(frame, result):
    expected = list(SCHEMA_COLUMNS)
    columns = list(frame.columns)
    duplicates = [name for name, count in Counter(columns).items() if count > 1]
    if duplicates:
        result.fail("schema", f"duplicate column names: {', '.join(duplicates)}")
        return False

    missing = [name for name in expected if name not in frame.columns]
    unexpected = [name for name in columns if name not in SCHEMA_COLUMNS]
    if missing:
        result.fail("schema", f"missing required columns: {', '.join(missing)}")
    if "ja4_hash_enc" in frame.columns:
        result.fail("schema", "unexpected model-only column: ja4_hash_enc")
    other_model_only = [name for name in unexpected if name in MODEL_ONLY_COLUMNS and name != "ja4_hash_enc"]
    if other_model_only:
        result.fail("schema", f"unexpected model-only columns: {', '.join(other_model_only)}")
    other_unexpected = [name for name in unexpected if name not in MODEL_ONLY_COLUMNS]
    if other_unexpected:
        result.fail("schema", f"unexpected durable columns: {', '.join(other_unexpected)}")
    if not missing and not unexpected and columns != expected:
        result.fail("schema", "durable schema column order differs from SCHEMA_COLUMNS")
    if "ja4_hash" not in frame.columns:
        result.fail("schema", "missing durable raw column: ja4_hash")
    if "schema" not in result.checks:
        result.checks["schema"] = True
    return True


def _validate_flow_ids(frame, result):
    if "flow_id" not in frame.columns:
        result.fail("flow_id uniqueness", "flow_id column is unavailable for validation")
        return
    blank_count = sum(_blank(value) for value in frame["flow_id"])
    if blank_count:
        result.fail("flow_id uniqueness", f"blank flow_id values: {blank_count}")
    duplicate_count = int(frame["flow_id"].duplicated(keep=False).sum())
    if duplicate_count:
        result.fail("flow_id uniqueness", f"duplicate flow_id values: {duplicate_count}")
    if "flow_id uniqueness" not in result.checks:
        result.checks["flow_id uniqueness"] = True


def _validate_numeric(frame, result):
    for name in NUMERIC_SCHEMA_FIELDS:
        if name not in frame.columns:
            continue
        values = frame[name]
        if not pd.api.types.is_numeric_dtype(values) or pd.api.types.is_bool_dtype(values):
            result.fail("numeric validity", f"non-numeric values in {name}")
            continue
        non_finite = int((~values.map(lambda value: isinstance(value, Real) and math.isfinite(value))).sum())
        if non_finite:
            result.fail("numeric validity", f"non-finite {name} values: {non_finite}")
            continue
        if name in {"src_port", "dst_port"}:
            invalid_ports = int(((values < 0) | (values > 65535) | (values % 1 != 0)).sum())
            if invalid_ports:
                result.fail("numeric validity", f"invalid {name} values: {invalid_ports}")
        elif name in INT_SCHEMA_FIELDS:
            invalid_integers = int(((values < 0) | (values % 1 != 0)).sum())
            if invalid_integers:
                result.fail("numeric validity", f"invalid non-negative integer {name} values: {invalid_integers}")
        elif name in NON_NEGATIVE_FIELDS:
            negative_count = int((values < 0).sum())
            if negative_count:
                result.fail("numeric validity", f"negative {name} values: {negative_count}")
    if "numeric validity" not in result.checks:
        result.checks["numeric validity"] = True


def _validate_booleans(frame, result):
    for name in BOOL_SCHEMA_FIELDS:
        if name not in frame.columns:
            continue
        invalid_count = sum(not _boolean_value(value) for value in frame[name])
        if invalid_count:
            result.fail("booleans", f"invalid {name} boolean values: {invalid_count}")
    if "booleans" not in result.checks:
        result.checks["booleans"] = True


def _validate_labels(frame, result, require_label):
    if "label" not in frame.columns:
        result.fail("labels", "label column is unavailable for validation")
        return
    labels = frame["label"]
    for value in labels:
        result.label_counts["<unlabeled>" if _missing(value) else str(value)] += 1
    blank_count = sum(not _missing(value) and not str(value).strip() for value in labels)
    if blank_count:
        result.fail("labels", f"blank label values: {blank_count}")
    missing_count = sum(_missing(value) for value in labels)
    if require_label and missing_count:
        result.fail("labels", f"unlabeled rows: {missing_count}")
    invalid_labels = sorted(
        {
            str(value)
            for value in labels
            if not _missing(value) and str(value).strip() not in DURABLE_LABEL_VALUES
        }
    )
    if invalid_labels:
        result.fail("labels", f"invalid labels: {', '.join(invalid_labels)}")
    if "labels" not in result.checks:
        result.checks["labels"] = True


def validate_dataframe(frame, path="<dataframe>", require_label=False):
    """Validate one durable-schema dataframe without fitting model preprocessing state."""
    result = ValidationResult(path=Path(path), row_count=len(frame), column_count=len(frame.columns))
    if frame.empty:
        result.fail("file", "dataframe is empty")
        return result
    if not _validate_schema(frame, result):
        return result
    _validate_flow_ids(frame, result)
    _validate_numeric(frame, result)
    _validate_booleans(frame, result)
    _validate_labels(frame, result, require_label)
    return result


def validate_file(path, require_label=False):
    """Read and validate one Parquet file, reporting read errors as validation failures."""
    path = Path(path)
    result = ValidationResult(path=path)
    if not path.is_file():
        result.fail("file", "path does not exist or is not a file")
        return result
    try:
        frame = pd.read_parquet(path)
    except Exception as error:
        result.fail("file", f"cannot read Parquet: {error}")
        return result
    return validate_dataframe(frame, path=path, require_label=require_label)


def print_result(result):
    print(f"FILE: {result.path}")
    print(f"STATUS: {'PASS' if result.passed else 'FAIL'}")
    if result.row_count or result.column_count:
        print(f"Rows: {result.row_count}")
        print(f"Columns: {result.column_count}")
    if result.label_counts:
        print("Label counts:")
        for label, count in sorted(result.label_counts.items()):
            print(f"  {label}: {count}")
    print("JA4 contract:")
    print(f"  raw ja4_hash persisted: {'yes' if 'ja4_hash' in SCHEMA_COLUMNS else 'no'}")
    print(f"  ja4_hash_enc persisted: {'yes' if 'ja4_hash_enc' in SCHEMA_COLUMNS else 'no'}")
    print("Checks:")
    for name in ("file", "schema", "flow_id uniqueness", "numeric validity", "labels", "booleans"):
        print(f"  {name}: {'PASS' if result.checks.get(name, True) else 'FAIL'}")
    for error in result.errors:
        print(f"- {error}")


def _expand_paths(paths):
    for path in paths:
        matches = glob.glob(str(path))
        yield from (matches or [path])


def main(argv=None):
    parser = argparse.ArgumentParser(description="Validate durable feature Parquet files before training handoff.")
    parser.add_argument("files", nargs="+", help="Parquet file paths or glob patterns")
    parser.add_argument(
        "--require-label",
        action="store_true",
        help="Fail rows with null labels; use for labeled training datasets.",
    )
    args = parser.parse_args(argv)

    results = [validate_file(path, require_label=args.require_label) for path in _expand_paths(args.files)]
    for result in results:
        print_result(result)
    failed = sum(not result.passed for result in results)
    print(f"Validated: {len(results)} files")
    print(f"Passed: {len(results) - failed}")
    print(f"Failed: {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
