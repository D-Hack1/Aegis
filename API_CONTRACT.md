# Aegis API Contract
> **Version:** 1.0  
> **Base URL:** `http://localhost:8000`  
> **Updated:** Day 1  
> **Owner:** Ebin (Backend) — ping for any shape mismatches before building around them

---

## General Rules

- All request and response bodies are **JSON**
- All timestamps are **ISO 8601 UTC** strings — `"2025-09-04T21:30:00.000Z"`
- All endpoints return `Content-Type: application/json`
- CORS is enabled for `http://localhost:5173` (Vite dev server)
- On error, every endpoint returns the same error shape:
  ```json
  {
    "detail": "Human-readable error message"
  }
  ```

---

## Severity Levels

Used across alerts and kill chains. Map to colours in the UI.

| Value | Colour | Meaning |
|---|---|---|
| `"critical"` | 🔴 Red | Confidence ≥ 0.90 |
| `"high"` | 🟠 Orange | Confidence ≥ 0.75 |
| `"medium"` | 🟡 Yellow | Confidence ≥ 0.50 |
| `"info"` | 🔵 Blue | Confidence < 0.50 or anomaly only |

---

## Threat Classes

| Value | Description |
|---|---|
| `"ddos"` | SYN flood, UDP flood |
| `"c2_beaconing"` | Botnet C2 periodic communication |
| `"dns_anomaly"` | DGA domains, DNS tunnelling |
| `"malware_tls"` | Malware inside encrypted sessions |
| `"port_scan"` | Reconnaissance / port scanning |
| `"exfiltration"` | Data exfiltration |
| `"unknown_anomaly"` | Detected by Isolation Forest, outside known classes |
| `"benign"` | Normal traffic — will NOT appear in `/alerts` |

---

## Endpoints

---

### `POST /infer`
> Internal use — called by `kafka/consumer.py`. Jaith does not need to call this.

---

### `GET /alerts`

Returns a paginated list of alerts. Poll this every 5 seconds for the live feed.

**Query Parameters**

| Param | Type | Required | Default | Description |
|---|---|---|---|---|
| `page` | integer | No | `1` | Page number (1-indexed) |
| `page_size` | integer | No | `20` | Results per page (max 100) |
| `severity` | string | No | — | Filter by severity: `critical`, `high`, `medium`, `info` |
| `threat_class` | string | No | — | Filter by threat class (see table above) |
| `start_time` | string | No | — | ISO 8601 UTC — only return alerts after this time |
| `end_time` | string | No | — | ISO 8601 UTC — only return alerts before this time |
| `src_ip` | string | No | — | Filter by source IP address |

**Example Request**
```
GET /alerts?page=1&page_size=20&severity=critical
GET /alerts?threat_class=c2_beaconing&start_time=2025-09-04T20:00:00Z
```

**Response `200 OK`**
```json
{
  "total": 142,
  "page": 1,
  "page_size": 20,
  "pages": 8,
  "results": [
    {
      "id": "abc123def456",
      "timestamp": "2025-09-04T21:30:00.000Z",
      "flow_id": "CmFTSk3bQhXgPzL19",
      "src_ip": "10.10.0.2",
      "dst_ip": "10.10.0.5",
      "src_port": 54321,
      "dst_port": 443,
      "protocol": "tcp",
      "threat_class": "c2_beaconing",
      "severity": "critical",
      "confidence": 0.94,
      "anomaly_score": 0.72,
      "evidence": [
        "Repeated communication at fixed intervals",
        "Unusual TLS client fingerprint (JA3)",
        "Low destination IP entropy — narrow target set"
      ],
      "kill_chain_id": "kc-uuid-1234"
    }
  ]
}
```

**Notes**
- `id` is the Elasticsearch document ID — use this for `/alerts/{id}`
- `evidence` is an array of human-readable strings (1–5 items), never empty on a positive detection
- `kill_chain_id` is `null` if this alert is not part of a multi-stage attack chain
- `anomaly_score` is `0.0–1.0` — higher = more anomalous
- `confidence` is `0.0–1.0`

---

### `GET /alerts/{id}`

Returns a single alert by its Elasticsearch document ID.

**Path Parameters**

| Param | Type | Description |
|---|---|---|
| `id` | string | Alert ID from `/alerts` results |

**Example Request**
```
GET /alerts/abc123def456
```

**Response `200 OK`**
```json
{
  "id": "abc123def456",
  "timestamp": "2025-09-04T21:30:00.000Z",
  "flow_id": "CmFTSk3bQhXgPzL19",
  "src_ip": "10.10.0.2",
  "dst_ip": "10.10.0.5",
  "src_port": 54321,
  "dst_port": 443,
  "protocol": "tcp",
  "duration": 12.4,
  "threat_class": "c2_beaconing",
  "severity": "critical",
  "confidence": 0.94,
  "anomaly_score": 0.72,
  "evidence": [
    "Repeated communication at fixed intervals",
    "Unusual TLS client fingerprint (JA3)",
    "Low destination IP entropy — narrow target set"
  ],
  "kill_chain_id": "kc-uuid-1234",
  "ja3_hash": "a0e9f5d64349fb13191bc781f81f42e1",
  "ja4_hash": "t13d1516h2_8daaf6152771_b0da82dd1658",
  "is_quic": false,
  "quic_0rtt": false
}
```

**Response `404 Not Found`**
```json
{
  "detail": "Alert abc123def456 not found"
}
```

---

### `GET /stats`

Returns aggregated traffic statistics for the dashboard charts. Auto-refresh every 30 seconds.

**Query Parameters**

| Param | Type | Required | Default | Description |
|---|---|---|---|---|
| `hours` | integer | No | `1` | How many hours back to aggregate (max 24) |

**Example Request**
```
GET /stats
GET /stats?hours=6
```

**Response `200 OK`**
```json
{
  "total_alerts": 142,
  "by_threat_class": {
    "ddos": 34,
    "c2_beaconing": 28,
    "dns_anomaly": 19,
    "malware_tls": 22,
    "port_scan": 15,
    "exfiltration": 12,
    "unknown_anomaly": 12
  },
  "by_severity": {
    "critical": 41,
    "high": 55,
    "medium": 33,
    "info": 13
  },
  "timeline": [
    {
      "bucket": "2025-09-04T20:00:00.000Z",
      "count": 8
    },
    {
      "bucket": "2025-09-04T20:05:00.000Z",
      "count": 14
    }
  ],
  "top_src_ips": [
    { "ip": "10.10.0.2", "count": 47 },
    { "ip": "10.10.0.3", "count": 31 }
  ]
}
```

**Notes**
- `timeline` buckets are **5-minute intervals** covering the requested `hours` window
- `top_src_ips` returns the top 10 source IPs by alert count
- `by_threat_class` only includes classes that have at least 1 alert — missing keys mean zero count

---

### `GET /kill-chains`

Returns correlated multi-stage attack chains. Each chain links alerts from the same source IP that triggered multiple different threat classes within a time window.

**Query Parameters**

| Param | Type | Required | Default | Description |
|---|---|---|---|---|
| `hours` | integer | No | `1` | How many hours back to look (max 24) |

**Example Request**
```
GET /kill-chains
```

**Response `200 OK`**
```json
{
  "total": 3,
  "chains": [
    {
      "chain_id": "kc-uuid-1234",
      "src_ip": "10.10.0.2",
      "first_seen": "2025-09-04T20:15:00.000Z",
      "last_seen": "2025-09-04T21:30:00.000Z",
      "stage_count": 3,
      "max_severity": "critical",
      "stages": [
        {
          "alert_id": "xyz789",
          "timestamp": "2025-09-04T20:15:00.000Z",
          "threat_class": "port_scan",
          "severity": "medium",
          "confidence": 0.87,
          "dst_ip": "10.10.0.5",
          "dst_port": 0,
          "evidence": ["Single source contacted many ports or hosts"]
        },
        {
          "alert_id": "abc123",
          "timestamp": "2025-09-04T20:45:00.000Z",
          "threat_class": "malware_tls",
          "severity": "high",
          "confidence": 0.81,
          "dst_ip": "10.10.0.5",
          "dst_port": 443,
          "evidence": ["Unusual TLS client fingerprint (JA4)", "QUIC 0-RTT resumption detected"]
        },
        {
          "alert_id": "def456",
          "timestamp": "2025-09-04T21:30:00.000Z",
          "threat_class": "c2_beaconing",
          "severity": "critical",
          "confidence": 0.94,
          "dst_ip": "10.10.0.5",
          "dst_port": 443,
          "evidence": ["Repeated communication at fixed intervals"]
        }
      ]
    }
  ]
}
```

**Notes**
- `stages` are sorted by `timestamp` ascending — earliest stage first
- `max_severity` is the highest severity across all stages in the chain — use this to colour the chain border
- A chain always has 2+ stages — single-alert detections never appear here
- `dst_port: 0` means the scan covered many ports — no single port to show

---

### `GET /metrics` ← SSE endpoint

Server-Sent Events stream of live pipeline throughput metrics. Published every 2 seconds. Connect once and keep the connection open — do not poll this endpoint.

**How to connect (browser)**
```javascript
const source = new EventSource('http://localhost:8000/metrics');

source.onmessage = (event) => {
  const data = JSON.parse(event.data);
  // update your UI with data
};

source.onerror = () => {
  // show disconnected state, EventSource auto-reconnects
};
```

**Event shape** — each `data:` payload is a JSON object:
```json
{
  "ts": "2025-09-04T21:30:02.000Z",
  "flows_per_sec": 84.5,
  "bytes_per_sec": 142300.0,
  "kafka_queue_depth": 12,
  "pipeline_latency_ms": 43.2,
  "latency_ms_mean": 47.8,
  "window_flows": 169
}
```

| Field | Type | Description |
|---|---|---|
| `ts` | string | Timestamp of this measurement |
| `flows_per_sec` | float | Flows processed per second in the last 2s window |
| `bytes_per_sec` | float | Raw bytes consumed per second in the last 2s window |
| `kafka_queue_depth` | integer | Unconsumed messages on `raw-features` topic (`-1` if query failed) |
| `pipeline_latency_ms` | float | Latency of the most recent `/infer` call in ms |
| `latency_ms_mean` | float | Mean latency across all calls in the last 2s window |
| `window_flows` | integer | Total flows processed in the last 2s window |

**Status dot thresholds**
```
pipeline_latency_ms < 100   → green
pipeline_latency_ms < 500   → yellow
pipeline_latency_ms >= 500  → red
```

---

### `GET /health`

Health check for the global API status bar. Poll every 10 seconds.

**Response `200 OK`** — all systems up
```json
{
  "status": "ok",
  "uptime_seconds": 3600,
  "model_loaded": true,
  "isolation_forest_loaded": true,
  "kafka": {
    "status": "ok",
    "bootstrap": "localhost:9092"
  },
  "elasticsearch": {
    "status": "ok",
    "host": "localhost:9200",
    "index": "alerts"
  }
}
```

**Response `200 OK`** — partial degradation (still 200, not 500 — check `status` field)
```json
{
  "status": "degraded",
  "uptime_seconds": 120,
  "model_loaded": true,
  "isolation_forest_loaded": true,
  "kafka": {
    "status": "error",
    "detail": "Cannot reach broker at localhost:9092"
  },
  "elasticsearch": {
    "status": "ok",
    "host": "localhost:9200",
    "index": "alerts"
  }
}
```

**UI behaviour**
- `status: "ok"` → green dot
- `status: "degraded"` → yellow dot  
- Any network error (can't reach `/health` at all) → red dot

---

## Pagination Pattern

All paginated endpoints follow the same shape. Example iteration:

```javascript
// Fetch all pages
let page = 1;
let allAlerts = [];

while (true) {
  const res = await fetch(`/alerts?page=${page}&page_size=100`);
  const data = await res.json();
  allAlerts = [...allAlerts, ...data.results];
  if (page >= data.pages) break;
  page++;
}
```

For the live feed, just always fetch `page=1` — you want the newest alerts, not all of them.

---

## TypeScript Interfaces

Copy these into `src/api/types.ts` — use them everywhere.

```typescript
export type Severity     = "critical" | "high" | "medium" | "info";
export type ThreatClass  =
  | "ddos" | "c2_beaconing" | "dns_anomaly" | "malware_tls"
  | "port_scan" | "exfiltration" | "unknown_anomaly" | "benign";

export interface Alert {
  id:             string;
  timestamp:      string;
  flow_id:        string;
  src_ip:         string;
  dst_ip:         string;
  src_port:       number;
  dst_port:       number;
  protocol:       string;
  duration?:      number;
  threat_class:   ThreatClass;
  severity:       Severity;
  confidence:     number;       // 0.0 – 1.0
  anomaly_score:  number;       // 0.0 – 1.0
  evidence:       string[];
  kill_chain_id:  string | null;
  ja3_hash?:      string;
  ja4_hash?:      string;
  is_quic?:       boolean;
  quic_0rtt?:     boolean;
}

export interface AlertsResponse {
  total:     number;
  page:      number;
  page_size: number;
  pages:     number;
  results:   Alert[];
}

export interface TimelineBucket {
  bucket: string;   // ISO timestamp of the 5-min bucket start
  count:  number;
}

export interface TopIp {
  ip:    string;
  count: number;
}

export interface StatsResponse {
  total_alerts:    number;
  by_threat_class: Record<ThreatClass, number>;
  by_severity:     Record<Severity, number>;
  timeline:        TimelineBucket[];
  top_src_ips:     TopIp[];
}

export interface KillChainStage {
  alert_id:     string;
  timestamp:    string;
  threat_class: ThreatClass;
  severity:     Severity;
  confidence:   number;
  dst_ip:       string;
  dst_port:     number;
  evidence:     string[];
}

export interface KillChain {
  chain_id:     string;
  src_ip:       string;
  first_seen:   string;
  last_seen:    string;
  stage_count:  number;
  max_severity: Severity;
  stages:       KillChainStage[];
}

export interface KillChainsResponse {
  total:  number;
  chains: KillChain[];
}

export interface PipelineMetrics {
  ts:                   string;
  flows_per_sec:        number;
  bytes_per_sec:        number;
  kafka_queue_depth:    number;
  pipeline_latency_ms:  number;
  latency_ms_mean:      number;
  window_flows:         number;
}

export interface ServiceStatus {
  status:  "ok" | "error";
  detail?: string;
}

export interface HealthResponse {
  status:                   "ok" | "degraded";
  uptime_seconds:           number;
  model_loaded:             boolean;
  isolation_forest_loaded:  boolean;
  kafka:                    ServiceStatus & { bootstrap?: string };
  elasticsearch:            ServiceStatus & { host?: string; index?: string };
}
```

---

## Severity Colour Map (Tailwind)

```typescript
export const SEVERITY_COLOURS: Record<Severity, string> = {
  critical: "bg-red-500 text-white",
  high:     "bg-orange-500 text-white",
  medium:   "bg-yellow-400 text-black",
  info:     "bg-blue-500 text-white",
};

export const SEVERITY_BORDER: Record<Severity, string> = {
  critical: "border-red-500",
  high:     "border-orange-500",
  medium:   "border-yellow-400",
  info:     "border-blue-500",
};

export const THREAT_CLASS_LABELS: Record<ThreatClass, string> = {
  ddos:            "DDoS",
  c2_beaconing:    "C2 Beaconing",
  dns_anomaly:     "DNS Anomaly",
  malware_tls:     "Malware (TLS)",
  port_scan:       "Port Scan",
  exfiltration:    "Exfiltration",
  unknown_anomaly: "Unknown Anomaly",
  benign:          "Benign",
};
```