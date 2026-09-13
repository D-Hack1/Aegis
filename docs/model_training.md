# Model Training Dataset Integration

## Dataset Structure

Generated profile data is organized as independent traffic runs:

```text
data/raw/profiles/<attack_scenario>/<run_id>.pcap
zeek/logs/profiles/<attack_scenario>/<run_id>/
data/features/profiles/<attack_scenario>/<run_id>.parquet
data/features/profiles/run_manifest.csv
```

The processing relationship is:

```text
traffic run -> PCAP -> isolated Zeek logs -> independent Parquet -> manifest entry
```

Each run represents an independent traffic capture. Its `run_id` must remain associated with every loaded flow until train, validation, and test assignment is complete.

The feature pipeline processes one Zeek log directory at a time and writes an independent Parquet for that run. The durable `flow_id` corresponds to the Zeek connection UID.

---

## Available Profile Runs

The current validated local dataset contains **24 successful independent runs**, with six profiles for each of four traffic scenarios.

| Traffic scenario | Profiles |
| --- | --- |
| `syn_flood` | `low_steady`, `medium_steady`, `high_steady`, `bursty`, `jittered`, `multi_port` |
| `udp_flood` | `low_steady`, `medium_steady`, `high_steady`, `bursty`, `jittered`, `multi_port` |
| `port_scan` | `fast_sequential`, `slow_sequential`, `fast_random`, `slow_random`, `common_ports`, `broad_sparse` |
| `dns_tunnel` | `short_sparse`, `steady_medium`, `baseline_large`, `long_lived`, `dense_batches`, `rotating_batches` |

These four scenario families represent the currently generated profile dataset and do not constitute the complete project attack taxonomy.

---

## Class Mapping

Traffic scenario and profile identify how a capture was generated. The model class is determined separately using the project's canonical label mapping.

| Traffic scenario | Model class |
| --- | --- |
| `syn_flood` | `ddos` |
| `udp_flood` | `ddos` |
| `port_scan` | `port_scan` |
| `dns_tunnel` | `dns_anomaly` |

For example, SYN flood and UDP flood are distinct traffic scenarios but both map to the `ddos` model class.

Other project scenarios should continue to use the existing canonical class mapping.

---

## Run Manifest

The validated local dataset includes:

```text
data/features/profiles/run_manifest.csv
```

It contains one row for every successful independent run.

| Column | Purpose |
| --- | --- |
| `run_id` | Stable independent-capture identity |
| `attack_scenario` | Traffic scenario used for canonical label lookup |
| `profile` | Generator profile identity |
| `pcap_path` | Source capture path |
| `zeek_log_dir` | Isolated Zeek output directory |
| `parquet_path` | Independent model-facing feature file |
| `seed` | Generator seed when applicable |
| `effective_generation_parameters` | Resolved generator parameters |
| `pcap_packet_count` | Packet count in the capture |
| `zeek_uid_count` | Unique Zeek connection UID count |
| `parquet_row_count` | Persisted feature-row count |
| `duplicate_flow_id_count` | Duplicate durable flow-ID count |

Training integration should primarily use `run_id`, `attack_scenario`, and `parquet_path`.

The manifest is dataset metadata and does not replace the project's canonical class taxonomy.

For the current validated local dataset:

```text
manifest entries = 24
unique Zeek conn UID count = Parquet row count = unique flow_id count
duplicate flow_id count = 0
```

for every successful run.

Only manifest-listed successful runs should be considered part of this profile dataset.

---

## Critical Split Requirement

The split unit for generated profile data must be the **independent run/capture**, not an individual flow row.

All rows belonging to one `run_id` must be assigned wholly to exactly one of:

- train
- validation
- test

A `run_id` must never occur in more than one split.

Randomly splitting individual flows can place flows originating from the same generated capture into multiple dataset partitions. This creates capture-level leakage and can inflate evaluation performance.

Run-aware splitting prevents this specific form of leakage but does not by itself guarantee realistic generalization.

---

## Required Loader Integration

The current training loader scans only top-level Parquet files using:

```text
features_dir.glob("*.parquet")
```

It derives the scenario from the Parquet filename, maps that value to a label, and retains it as scenario metadata for splitting.

The current loader does **not**:

- recursively discover the profile Parquets
- consume `run_manifest.csv`
- preserve `run_id` as the independent capture grouping key

Integration of the profile dataset therefore requires the training loader to:

1. Load runs using `run_manifest.csv` or recursively discover the profile Parquets.
2. Attach the corresponding `run_id` to every loaded flow.
3. Map `attack_scenario` to the canonical model class.
4. Concatenate runs only after run identity has been preserved.
5. Assign whole runs to train, validation, and test.
6. Remove `run_id` from predictive model features after the split if it is retained only as metadata.

The manifest-based approach is preferred because it explicitly preserves capture identity and scenario metadata.

---

## Split Validation

After assigning runs to train, validation, and test, verify:

```text
train run IDs ∩ validation run IDs = empty
train run IDs ∩ test run IDs = empty
validation run IDs ∩ test run IDs = empty
```

The training report should also include:

- number of runs per split
- number of flow rows per split
- class distribution per split

This makes the absence of capture-level leakage directly verifiable.

---

## Dataset Diversity

Traffic profiles introduce intra-class variation so that training data does not consist only of repeated instances of one fixed synthetic attack pattern.

### SYN and UDP Flood

Profiles vary applicable combinations of:

- traffic intensity
- steady versus bursty behavior
- timing jitter
- destination-port behavior
- payload or byte characteristics

### Port Scan

Profiles vary:

- scan speed
- sequential versus randomized ordering
- port range and cardinality
- source-port behavior
- scan intensity

### DNS Tunnel

DNS-tunnel profiles use authentic iodine traffic and vary:

- session count
- session duration
- session density
- batching behavior
- timing characteristics

These profiles improve intra-class diversity but do not establish generalization to real-world production traffic.

---

## Evaluation Guidance

After integrating the profile dataset with run-aware splitting, report at minimum:

- accuracy
- macro F1
- weighted F1
- per-class precision
- per-class recall
- per-class F1
- confusion matrix
- train, validation, and test run counts
- class distribution per split
- explicit confirmation of zero `run_id` overlap

If evaluation performance remains unusually high, investigate the dataset rather than intentionally attempting to reduce model performance.

Relevant checks include:

- insufficient benign traffic diversity
- deterministic synthetic attack fingerprints
- insufficient variation in other attack classes
- accidental train/test leakage
- scenario-specific artifacts that make classes trivially separable

The purpose of the profile dataset is to improve variation and evaluation validity, not to guarantee a particular F1 score.

---

## Generated Artifact Availability

The repository `.gitignore` excludes generated data, including:

```text
data/raw/
data/features/
*.pcap
*.parquet
zeek/logs/
```

Therefore, generated PCAPs, Zeek logs, feature Parquets, and the run manifest may not be present in a fresh clone of the repository.

The current 24-run dataset and manifest have been generated and validated locally, but their presence should not be assumed from the repository alone.

The generator implementation and associated tests are version-controlled; generated dataset artifacts should be transferred or regenerated separately according to the project's data-sharing workflow.

Large generated artifacts should not be force-added to Git solely to make them available to training.

---

## Current Integration Status

| Item | Status |
| --- | --- |
| Traffic profile generators | Implemented in repository |
| Independent profile runs | Generated and validated locally |
| Per-run feature Parquets | Generated and validated locally |
| Run manifest | Generated and validated locally |
| Run-level integrity validation | Complete |
| Run-aware training loader | Not integrated |
| Run-aware retraining and evaluation | Pending |

The next integration step is to update model training to consume the independent profile runs while preserving `run_id` through dataset splitting.