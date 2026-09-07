# Aegis --- Passive AI/ML Network Threat Detection

> **Smart India Hackathon 2026 \| Problem Statement 145**

Aegis is a passive, AI/ML-powered network threat detection platform
designed to observe network traffic without introducing an active
control path into the monitored network. It combines **Zeek network
telemetry, feature engineering, Kafka streaming, machine learning,
anomaly detection, SHAP explainability, FastAPI, Elasticsearch, and a
real-time React dashboard** into a single end-to-end detection pipeline.

The system is designed for controlled, isolated experimentation with
realistic attack and benign traffic scenarios.

------------------------------------------------------------------------

## Table of Contents

-   [Overview](#overview)
-   [Why Aegis](#why-aegis)
-   [Core Capabilities](#core-capabilities)
-   [Detection Scenarios](#detection-scenarios)
-   [System Architecture](#system-architecture)
-   [Data Flow](#data-flow)
-   [Feature Engineering](#feature-engineering)
-   [ML Detection](#ml-detection)
-   [Explainability](#explainability)
-   [Streaming Pipeline](#streaming-pipeline)
-   [Alert Correlation and Kill
    Chains](#alert-correlation-and-kill-chains)
-   [Dashboard](#dashboard)
-   [Project Structure](#project-structure)
-   [Team Responsibilities](#team-responsibilities)
-   [Getting Started](#getting-started)
-   [Configuration](#configuration)
-   [Testing](#testing)
-   [Evaluation](#evaluation)
-   [Security and Isolation](#security-and-isolation)
-   [Development Workflow](#development-workflow)
-   [Project Status](#project-status)
-   [Future Extensions](#future-extensions)

------------------------------------------------------------------------

## Overview

Traditional network monitoring systems often generate large volumes of
low-level telemetry that must be manually inspected or processed by
separate security tools.

Aegis creates a unified pipeline:

``` text
                    ┌─────────────────────┐
                    │   Network Traffic   │
                    │ PCAP / Live Traffic │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │       Zeek          │
                    │ Network Telemetry   │
                    └──────────┬──────────┘
                               │
               ┌───────────────┼────────────────┐
               ▼               ▼                ▼
           conn.log         dns.log          ssl.log
                                                │
                                             quic.log
               └───────────────┬────────────────┘
                               ▼
                    ┌─────────────────────┐
                    │ Feature Engineering │
                    │     Pipeline        │
                    └──────────┬──────────┘
                               │
                         FeatureRow
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Staging Queue     │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │       Kafka         │
                    │    raw-features     │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Kafka Consumer      │
                    │ → FastAPI /infer    │
                    └──────────┬──────────┘
                               │
                    ┌──────────┴──────────┐
                    ▼                     ▼
             Inference Result        Pipeline Metrics
                    │                     │
                    ▼                     ▼
             Elasticsearch          Kafka /metrics
                    │                     │
                    └──────────┬──────────┘
                               ▼
                    ┌─────────────────────┐
                    │   React Dashboard   │
                    │ Alerts / Stats /    │
                    │ Metrics / Kill Chain│
                    └─────────────────────┘
```

The project specification defines this as a multi-stage pipeline
connecting Docker-based traffic generation, Zeek, feature engineering,
Kafka, ML inference, Elasticsearch, FastAPI, and the frontend dashboard.

------------------------------------------------------------------------

## Why Aegis

Aegis focuses on **passive detection** rather than active network
intervention.

The system:

-   Observes traffic and network metadata.
-   Converts network telemetry into ML-ready feature rows.
-   Streams features through Kafka.
-   Combines supervised classification with unsupervised anomaly
    detection.
-   Produces human-readable evidence using SHAP.
-   Stores positive detections for investigation.
-   Correlates multiple detections into possible attack kill chains.
-   Exposes live operational metrics for throughput and latency.
-   Presents security events through a centralized dashboard.

------------------------------------------------------------------------

## Core Capabilities

### Passive Network Monitoring

Zeek processes captured traffic and produces structured logs such as:

-   `conn.log`
-   `dns.log`
-   `ssl.log`
-   `http.log`
-   `quic.log`

### Feature Engineering

The feature pipeline derives:

-   Flow-level traffic statistics
-   Source/destination fan-out and fan-in
-   Inter-arrival-time statistics
-   Connection frequency
-   Destination entropy
-   DNS characteristics
-   TLS fingerprints
-   JA3 / JA3S / JA4 fingerprints
-   QUIC metadata

### Machine Learning

Aegis combines:

-   **XGBoost** for known threat classification
-   **Isolation Forest** for anomaly detection outside the known classes

### Explainable Detection

SHAP is used to identify important features behind individual
predictions and convert them into human-readable evidence.

### Real-Time Streaming

Kafka decouples feature extraction, inference, and downstream
processing.

### Alert Storage

Positive detections are written to Elasticsearch for querying,
filtering, aggregation, and correlation.

### Live Dashboard

The frontend provides:

-   Live alert feed
-   Alert details
-   Threat statistics
-   Throughput metrics
-   Kill-chain visualization
-   API/service status

------------------------------------------------------------------------

## Detection Scenarios

The project defines seven scenarios:

  Scenario            Detection Class
  ------------------- -----------------
  SYN flood           `ddos`
  UDP flood           `ddos`
  C2 beaconing        `c2_beaconing`
  DGA traffic         `dns_anomaly`
  DNS tunneling       `dns_anomaly`
  Port scan           `port_scan`
  Data exfiltration   `exfiltration`
  Benign traffic      `benign`

The specification groups the scenarios into seven labeled classes, with
SYN/UDP floods representing the DDoS class and DGA/DNS tunneling
representing DNS anomalies.

------------------------------------------------------------------------

## System Architecture

### 1. Isolated Traffic Lab

Docker containers provide controlled traffic generation and packet
capture.

The intended environment contains:

-   Attacker container
-   Victim container
-   Benign traffic container
-   Zeek container
-   Kafka + Zookeeper
-   Elasticsearch
-   Backend services
-   Frontend

The lab is intended to use an isolated Docker network with no external
routing.

### 2. Zeek

Zeek converts PCAP/network traffic into structured network telemetry.

Important logs include:

``` text
conn.log
dns.log
ssl.log
http.log
quic.log
```

TLS telemetry includes JA3 and JA3S, with JA4 added as an extended
fingerprinting capability.

### 3. Feature Pipeline

The feature pipeline consumes a Zeek log directory and creates one
feature row per network flow using Zeek's `uid` as the join key.

Output is stored as scenario-specific Parquet data.

Example:

``` text
data/features/
├── syn_flood.parquet
├── udp_flood.parquet
├── c2_beacon.parquet
├── dga.parquet
├── dns_tunnel.parquet
├── port_scan.parquet
├── exfiltration.parquet
└── benign.parquet
```

### 4. Kafka

Kafka provides asynchronous communication between feature extraction and
inference.

The main topics are:

``` text
raw-features
inference-results
alerts
pipeline-metrics
```

### 5. FastAPI

The backend provides the inference and monitoring API.

Core endpoints include:

``` text
POST /infer
GET  /alerts
GET  /alerts/{id}
GET  /stats
GET  /metrics
GET  /kill-chains
GET  /health
```

### 6. Elasticsearch

Elasticsearch stores confirmed positive detections and supports:

-   Filtering
-   Pagination
-   Threat-class aggregation
-   Time-based statistics
-   Source-IP analysis
-   Kill-chain correlation

### 7. React Dashboard

The frontend consumes the FastAPI APIs and displays security events and
operational metrics.

------------------------------------------------------------------------

## Data Flow

A typical feature row follows this path:

``` text
PCAP
  │
  ▼
Zeek
  │
  ├── conn.log
  ├── dns.log
  ├── ssl.log
  └── quic.log
  │
  ▼
features/pipeline.py
  │
  ▼
FeatureRow
  │
  ▼
Staging Queue
  │
  ▼
Kafka: raw-features
  │
  ▼
kafka/consumer.py
  │
  ▼
POST /infer
  │
  ├── XGBoost
  ├── Isolation Forest
  └── SHAP
  │
  ▼
Inference Result
  │
  ├── inference-results
  ├── alerts
  └── Elasticsearch
  │
  ▼
FastAPI
  │
  ▼
React Dashboard
```

------------------------------------------------------------------------

## Feature Engineering

Aegis uses multiple feature families.

### Flow Features

From `conn.log`:

``` text
packets_per_sec
bytes_per_sec
outbound_inbound_ratio
fan_out
fan_in
unique_dst_ips
unique_dst_ports
```

### Timing Features

``` text
iat_mean
iat_std
iat_min
iat_max
connection_frequency
periodicity_score
```

The periodicity score is intended to highlight highly regular
communication patterns that can indicate beaconing.

### Entropy Features

``` text
src_ip_entropy
dns_query_entropy
```

High DNS query entropy can be useful as a DGA indicator.

### DNS Features

``` text
domain_length_mean
domain_length_max
subdomain_count
dns_record_type_a_ratio
dns_record_type_txt_ratio
dns_query_count
```

### TLS Features

``` text
ja3_hash
ja3s_hash
ja4_hash
tls_version
cipher_suite_enc
is_tls
```

### QUIC Features

``` text
is_quic
quic_0rtt
quic_pkt_size_mean
quic_pkt_size_std
```

Non-QUIC flows are intended to receive zero-valued QUIC features.

------------------------------------------------------------------------

## ML Detection

### XGBoost

XGBoost performs multi-class threat classification.

The training pipeline is intended to:

1.  Combine feature datasets.
2.  Join features with labels.
3.  Handle class imbalance.
4.  Split data into training, validation, and test sets.
5.  Train a multi-class XGBoost classifier.
6.  Tune hyperparameters with Optuna.
7.  Evaluate precision, recall, and F1.
8.  Save the trained model.

Initial target:

``` text
F1 > 0.85 per class
```

The specification proposes a starting configuration around:

``` text
n_estimators = 200
max_depth = 6
learning_rate = 0.1
subsample = 0.8
eval_metric = mlogloss
```

### Isolation Forest

Isolation Forest is trained primarily on benign traffic.

Its purpose is to identify anomalous behavior that may not belong to the
known supervised classes.

The contamination parameter is tuned against benign validation data.

### Unified Inference

An inference result contains:

``` json
{
  "threat_class": "c2_beaconing",
  "confidence": 0.94,
  "anomaly_score": 0.71,
  "evidence_features": []
}
```

The final implementation may enrich the evidence field using SHAP
output.

------------------------------------------------------------------------

## Explainability

Aegis uses SHAP to explain individual model predictions.

The top contributing features are converted into human-readable
evidence.

Examples include:

  Feature                    Human-readable evidence
  -------------------------- -------------------------------------------------
  `periodicity_score`        Repeated communication at fixed intervals
  `fan_out`                  Single source contacted many ports or hosts
  `outbound_inbound_ratio`   Unusually large outbound data volume
  `dns_query_entropy`        High-entropy domain names (DGA indicator)
  `ja3_hash`                 Unusual TLS client fingerprint (JA3)
  `ja4_hash`                 Unusual TLS client fingerprint (JA4)
  `quic_pkt_size_std`        Irregular QUIC packet sizing
  `quic_0rtt`                QUIC 0-RTT resumption detected
  `src_ip_entropy`           Source IP scanning a wide range of destinations

The intended inference response contains the strongest evidence features
rather than exposing raw model internals to the dashboard.

------------------------------------------------------------------------

## Streaming Pipeline

Kafka separates the high-frequency feature generation stage from
inference.

### Producer

The producer:

1.  Reads feature rows from the staging queue.
2.  Serializes them as JSON.
3.  Publishes them to `raw-features`.
4.  Uses short batching windows to avoid waiting indefinitely for a
    large batch.

### Consumer

The consumer:

1.  Reads from `raw-features`.
2.  Deserializes the message into a `FeatureRow`.
3.  Records the arrival time.
4.  Sends the feature vector to `/infer`.
5.  Measures inference pipeline latency.
6.  Publishes the inference result.
7.  Publishes pipeline metrics.
8.  Handles malformed messages without crashing.

Malformed messages are written to a dead-letter log.

### Pipeline Metrics

The intended metrics stream contains values such as:

``` json
{
  "ts": "<ISO>",
  "flows_per_sec": 0,
  "bytes_per_sec": 0,
  "kafka_queue_depth": 0,
  "pipeline_latency_ms": 0
}
```

These metrics power the live throughput/latency view.

------------------------------------------------------------------------

## Alert Correlation and Kill Chains

Aegis can correlate multiple alerts from the same source into a possible
multi-stage attack.

The correlator is designed to:

1.  Examine recent alerts.
2.  Group alerts by source IP.
3.  Identify sources producing multiple threat classes.
4.  Assign a shared `kill_chain_id`.
5.  Update the corresponding Elasticsearch documents.
6.  Expose the resulting chains through `/kill-chains`.

The dashboard represents each kill chain as a timeline of attack stages.

------------------------------------------------------------------------

## Dashboard

The React dashboard is designed around four major operational views.

### Live Feed

Displays recent alerts with:

-   Timestamp
-   Source IP
-   Destination IP
-   Threat class
-   Severity
-   Confidence

### Alert Detail

Displays:

-   Complete flow tuple
-   Threat class
-   Confidence
-   Anomaly score
-   Evidence
-   Kill-chain relationship

### Statistics

Displays:

-   Threat-class distribution
-   Alert volume over time
-   Top source IPs

### Throughput / Metrics

Displays:

-   Flows/sec
-   MB/sec
-   Kafka queue depth
-   Pipeline latency

### Kill Chains

Displays:

-   Source IP
-   Attack stages
-   Timestamp
-   Confidence
-   Severity

------------------------------------------------------------------------

## Project Structure

The target repository structure is:

``` text
Aegis/
│
├── docker-compose.yml
├── .env
├── .env.example
├── Makefile
├── LAB.md
├── INTEGRATION.md
├── API_CONTRACT.md
├── README.md
│
├── attacker/
│   ├── Dockerfile
│   └── scripts/
│       ├── c2_beacon.py
│       ├── exfiltration.py
│       ├── dga.py
│       ├── syn_flood.py
│       ├── udp_flood.py
│       ├── port_scan.py
│       └── dns_tunnel.py
│
├── victim/
│   └── Dockerfile
│
├── benign/
│   ├── Dockerfile
│   └── scripts/
│       └── benign_traffic.py
│
├── data/
│   ├── raw/
│   │   └── *.pcap
│   ├── labels/
│   │   └── *.json
│   └── features/
│       └── *.parquet
│
├── zeek/
│   └── scripts/
│       ├── main.zeek
│       ├── ja3.zeek
│       └── quic.zeek
│
├── features/
│   ├── schema.py
│   ├── pipeline.py
│   └── watcher.py
│
├── kafka/
│   ├── producer.py
│   ├── consumer.py
│   ├── metrics_producer.py
│   └── health_check.py
│
├── ml/
│   ├── train.py
│   ├── evaluate.py
│   ├── inference.py
│   ├── explainability.py
│   ├── model.joblib
│   └── tests/
│       └── test_explainability.py
│
├── api/
│   ├── main.py
│   └── correlator.py
│
├── es/
│   ├── init_index.py
│   └── health_check.py
│
└── dashboard/
    └── src/
        ├── api/
        │   ├── alerts.ts
        │   ├── stats.ts
        │   ├── metrics.ts
        │   └── killChains.ts
        └── views/
            ├── LiveFeed.tsx
            ├── AlertDetail.tsx
            ├── Stats.tsx
            ├── Metrics.tsx
            └── KillChains.tsx
```

------------------------------------------------------------------------

## Team Responsibilities

  -----------------------------------------------------------------------
  Team Member             Role                    Main Responsibility
  ----------------------- ----------------------- -----------------------
  Nived                   DevOps / Pipeline       Docker lab, Kafka,
                                                  Elasticsearch,
                                                  integration

  Ebin                    Backend                 Shared schema,
                                                  watcher/Kafka glue,
                                                  FastAPI, APIs,
                                                  correlation

  Aadi                    ML                      Traffic generation,
                                                  Zeek/QUIC work,
                                                  Isolation Forest,
                                                  inference

  Gowri                   ML                      Feature engineering,
                                                  JA3/JA4/QUIC features,
                                                  SHAP

  Sanjay                  ML                      Labels, dataset
                                                  preparation, XGBoost
                                                  training/evaluation

  Jaith                   Frontend                React dashboard and
                                                  visualization
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## Getting Started

### Prerequisites

The project is designed around:

-   Docker and Docker Compose
-   Python 3
-   Node.js/npm
-   Zeek
-   Kafka + Zookeeper
-   Elasticsearch
-   A modern web browser

The exact versions and installation commands should be kept in the
repository's environment/setup documentation.

### 1. Clone the repository

``` bash
git clone <repository-url>
cd Aegis
```

### 2. Configure environment variables

Create the local environment file from the example:

``` bash
cp .env.example .env
```

On Windows PowerShell:

``` powershell
Copy-Item .env.example .env
```

Do not commit secrets or machine-specific credentials.

### 3. Start the lab

Use the project's Docker/Makefile commands once configured:

``` bash
docker compose up -d
```

Verify the isolated network and service health before generating
traffic.

### 4. Generate traffic and capture PCAPs

Run the scenario scripts in the controlled lab.

Expected raw captures include:

``` text
data/raw/
├── syn_flood.pcap
├── udp_flood.pcap
├── c2_beacon.pcap
├── dga.pcap
├── dns_tunnel.pcap
├── port_scan.pcap
└── exfiltration.pcap
```

Benign traffic should also be generated for the benign dataset.

### DNS Tunnel Lab Workflow

The DNS-tunnel scenario uses iodine in the isolated Docker lab. The attacker
container (`10.10.0.2`) runs `iodined`; the victim container (`10.10.0.3`)
runs the iodine client. Both containers need `/dev/net/tun`.

The validated lab parameters are:

```text
domain: tunnel.lab
password: test
tunnel-side server address: 192.168.99.1
final victim capture: /pcaps/dns_tunnel.pcap
```

Run these commands in separate terminal sessions:

```bash
# Attacker (10.10.0.2)
iodined -f -P test 192.168.99.1 tunnel.lab

# Victim (10.10.0.3), start capture before the client
tcpdump -i eth0 -U -w /pcaps/dns_tunnel.pcap

# Victim (10.10.0.3)
iodine -f -P test 10.10.0.2 tunnel.lab
```

Use `python attacker/scripts/dns_tunnel.py --help` to print the same workflow
with configurable server, domain, password, tunnel-side address, and capture
path. The final capture is an authentic iodine session: direct client-to-server
operation exposes initial DNS negotiation and may then use raw UDP transport.
The `-r` DNS-forced experiment did not complete query-type autodetection and is
not the final workflow.

This hackathon lab simulates the authoritative DNS relationship within its
isolated Docker network. A real deployment would require DNS delegation of the
tunnel domain to the `iodined` endpoint; no public DNS delegation exists in
this lab.

### 5. Process traffic with Zeek

Run Zeek against the captured traffic and produce the required logs.

The feature pipeline consumes the Zeek log directory rather than
individual feature files.

### 6. Generate features

The feature engineering pipeline produces scenario-specific Parquet
files under:

``` text
data/features/
```

### 7. Train the models

Train the XGBoost classifier and Isolation Forest using the prepared
feature datasets.

The final artifacts are intended to include:

``` text
ml/model.joblib
ml/optuna_study.pkl
ml/classification_report.txt
ml/confusion_matrix.png
```

### 8. Start the backend

Start the FastAPI service and verify:

``` text
GET /health
```

The health endpoint is intended to report service dependencies, model
state, and uptime.

### 9. Start the dashboard

From the dashboard directory:

``` bash
npm install
npm run dev
```

The frontend connects to the FastAPI service and displays live
detections and metrics.

------------------------------------------------------------------------

## Configuration

Configuration should be supplied through environment variables rather
than hardcoded values.

Important variables include:

``` text
KAFKA_BOOTSTRAP
KAFKA_TOPIC_FEATURES
KAFKA_TOPIC_RESULTS
KAFKA_TOPIC_METRICS
KAFKA_CONSUMER_GROUP
INFER_URL
INFER_TIMEOUT
ES_HOST
ES_PORT
```

Keep local configuration in `.env` and provide safe
defaults/documentation in `.env.example`.

------------------------------------------------------------------------

## Testing

Aegis uses unit tests for individual pipeline components and integration
testing for the complete system.

Run the Python test suite with:

``` bash
pytest -v
```

Unit testing should cover areas such as:

-   Feature/schema validation
-   File watcher behavior
-   Feature serialization
-   Kafka producer behavior
-   Kafka consumer deserialization
-   Inference request handling
-   Rolling pipeline statistics
-   Explainability output

Integration testing should verify:

``` text
Traffic
  → Zeek
  → Feature Pipeline
  → Kafka
  → FastAPI
  → Elasticsearch
  → Dashboard
```

The integration environment should also verify that all required
services and Kafka topics are available.

------------------------------------------------------------------------

## Evaluation

The ML pipeline is intended to use:

``` text
70% Training
15% Validation
15% Test
```

with stratification by class.

Evaluation includes:

-   Precision
-   Recall
-   F1 score
-   Confusion matrix
-   Classification report
-   Anomaly-score analysis
-   Hyperparameter tuning results

The project specification sets a target of **F1 \> 0.85 per class**.

Model evaluation should be performed on held-out data that is not used
during training.

------------------------------------------------------------------------

## Security and Isolation

Aegis's traffic-generation environment is designed specifically for
controlled testing.

The Docker lab should:

-   Use a private isolated network.
-   Prevent external routing/NAT from the experiment network.
-   Keep attack tooling inside the lab.
-   Use dedicated attacker, victim, and benign containers.
-   Avoid exposing unnecessary victim ports.
-   Keep credentials and secrets outside source control.

Attack-generation scripts are intended for the isolated SIH test
environment only.

------------------------------------------------------------------------

## Development Workflow

Aegis is developed as a team project with component ownership.

A typical feature workflow is:

``` bash
git switch main
git pull --rebase origin main

git switch -c feature/<feature-name>

# make changes

pytest -v

git add .
git commit -m "Describe the change"

git push -u origin feature/<feature-name>
```

Create a Pull Request against `main` after testing.

Before merging a feature branch:

1.  Pull the latest `main`.
2.  Rebase the feature branch when appropriate.
3.  Run the test suite.
4.  Review the changed files.
5.  Push the final branch.
6.  Open the Pull Request.
7.  Merge after review.
8.  Delete the feature branch after successful merge if it is no longer
    needed.

------------------------------------------------------------------------

## Project Status

The architecture and component responsibilities are organized around a
staged build:

``` text
1. Docker + isolated traffic lab
             ↓
2. Traffic generation + PCAP capture
             ↓
3. Zeek telemetry
             ↓
4. Feature engineering
             ↓
5. Kafka streaming
             ↓
6. ML training + inference
             ↓
7. FastAPI + Elasticsearch
             ↓
8. React dashboard
             ↓
9. Full integration test + demo rehearsal
```

The project specification identifies the full integration test and PCAP
replay demonstration as the final validation stage.

------------------------------------------------------------------------

## Future Extensions

Potential extensions that fit naturally into the architecture include:

-   Additional network protocols and fingerprints
-   More anomaly-detection strategies
-   Online/continual model updates
-   Distributed Kafka deployments
-   More sophisticated alert correlation
-   Additional kill-chain stages
-   Historical performance analytics
-   Model drift monitoring
-   Automated dataset validation
-   Additional explainability methods

------------------------------------------------------------------------

## SIH 2026

**Project:** Aegis\
**Theme:** Passive AI/ML Network Threat Detection\
**Problem Statement:** 145\
**Focus:** Network telemetry → ML detection → explainable alerts →
real-time monitoring

Built as a collaborative SIH 2026 project with a focus on an end-to-end,
reproducible, isolated network-threat detection pipeline.
