"""

Aegis FastAPI application.

Endpoints:
    POST /infer
    GET  /alerts
    GET  /alerts/{id}
    GET  /stats
    GET  /kill-chains
    GET  /metrics      (SSE)
    GET  /health

Environment variables:
    ES_HOST              Elasticsearch host        (default: localhost)
    ES_PORT              Elasticsearch port        (default: 9200)
    ES_INDEX             Elasticsearch index name  (default: alerts)
    KAFKA_BOOTSTRAP      Kafka broker              (default: localhost:9092)
    KAFKA_TOPIC_METRICS  Metrics topic             (default: pipeline-metrics)
    MODEL_PATH           XGBoost model path        (default: ml/model.joblib)
    ISO_FOREST_PATH      Isolation Forest path     (default: ml/iso_forest.joblib)
    INFER_THRESHOLD      Min confidence to classify as threat (default: 0.5)
    CORS_ORIGIN          Frontend origin           (default: http://localhost:5173)
"""

import os
import sys
import json
import uuid
import asyncio
import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import AsyncGenerator, Optional

import joblib
import numpy as np
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from elasticsearch import AsyncElasticsearch, NotFoundError
from aiokafka import AIOKafkaConsumer

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from features.schema import FEATURE_COLUMNS, BOOL_COLUMNS, FILL_ZERO_COLUMNS

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("api.main")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
ES_HOST             = os.getenv("ES_HOST",             "localhost")
ES_PORT             = int(os.getenv("ES_PORT",         "9200"))
ES_INDEX            = os.getenv("ES_INDEX",            "alerts")
KAFKA_BOOTSTRAP     = os.getenv("KAFKA_BOOTSTRAP",     "localhost:9092")
KAFKA_TOPIC_METRICS = os.getenv("KAFKA_TOPIC_METRICS", "pipeline-metrics")
MODEL_PATH          = os.getenv("MODEL_PATH",          "ml/model.joblib")
ISO_FOREST_PATH     = os.getenv("ISO_FOREST_PATH",     "ml/iso_forest.joblib")
INFER_THRESHOLD     = float(os.getenv("INFER_THRESHOLD", "0.5"))
CORS_ORIGIN         = os.getenv("CORS_ORIGIN",         "http://localhost:5173")

THREAT_CLASSES = [
    "ddos",
    "c2_beaconing",
    "dns_anomaly",
    "malware_tls",
    "port_scan",
    "exfiltration",
    "benign",
]

SEVERITY_THRESHOLDS = {
    "critical": 0.90,
    "high":     0.75,
    "medium":   0.50,
    "info":     0.0,
}

# ---------------------------------------------------------------------------
# App state — models, ES client, startup time
# ---------------------------------------------------------------------------
class AppState:
    xgb_model        = None
    iso_forest       = None
    es: AsyncElasticsearch = None
    startup_time: float    = 0.0
    model_loaded: bool     = False
    iso_forest_loaded: bool = False


state = AppState()


# ---------------------------------------------------------------------------
# Lifespan — load models + connect ES on startup, clean up on shutdown
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    state.startup_time = time.monotonic()

    # --- Load XGBoost model ---
    if Path(MODEL_PATH).exists():
        try:
            state.xgb_model   = joblib.load(MODEL_PATH)
            state.model_loaded = True
            logger.info("XGBoost model loaded from %s", MODEL_PATH)
        except Exception as e:
            logger.critical("Failed to load XGBoost model: %s", e)
            raise RuntimeError(f"Cannot start — model load failed: {e}")
    else:
        logger.critical("Model file not found at %s — cannot start", MODEL_PATH)
        raise RuntimeError(f"Model file missing: {MODEL_PATH}")

    # --- Load Isolation Forest ---
    if Path(ISO_FOREST_PATH).exists():
        try:
            state.iso_forest        = joblib.load(ISO_FOREST_PATH)
            state.iso_forest_loaded = True
            logger.info("Isolation Forest loaded from %s", ISO_FOREST_PATH)
        except Exception as e:
            logger.critical("Failed to load Isolation Forest: %s", e)
            raise RuntimeError(f"Cannot start — Isolation Forest load failed: {e}")
    else:
        logger.critical("Isolation Forest file not found at %s — cannot start", ISO_FOREST_PATH)
        raise RuntimeError(f"Isolation Forest file missing: {ISO_FOREST_PATH}")

    # --- Connect Elasticsearch ---
    state.es = AsyncElasticsearch(
        hosts=[{"host": ES_HOST, "port": ES_PORT, "scheme": "http"}]
    )
    try:
        info = await state.es.info()
        logger.info("Elasticsearch connected — cluster: %s", info["cluster_name"])
    except Exception as e:
        logger.critical("Cannot connect to Elasticsearch at %s:%d — %s", ES_HOST, ES_PORT, e)
        raise RuntimeError(f"Elasticsearch unreachable: {e}")

    # --- Start correlator background task ---
    correlator_task = asyncio.create_task(_correlator_loop())
    logger.info("Correlator background task started")

    logger.info("Aegis API ready")
    yield

    # --- Shutdown ---
    correlator_task.cancel()
    try:
        await correlator_task
    except asyncio.CancelledError:
        pass
    await state.es.close()
    logger.info("Aegis API shut down cleanly")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Aegis — Network Threat Detection API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[CORS_ORIGIN],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class InferRequest(BaseModel):
    # Flow identity
    flow_id:   str
    ts:        float
    src_ip:    str
    dst_ip:    str
    src_port:  int
    dst_port:  int
    protocol:  str
    duration:  float

    # Volume
    packets_per_sec:        float
    bytes_per_sec:          float
    outbound_inbound_ratio: float
    orig_bytes:             int
    resp_bytes:             int
    orig_pkts:              int
    resp_pkts:              int

    # Fan-out / fan-in
    fan_out:          float
    fan_in:           float
    unique_dst_ips:   int
    unique_dst_ports: int

    # IAT
    iat_mean:             float
    iat_std:              float = 0.0
    iat_min:              float = 0.0
    iat_max:              float = 0.0
    connection_frequency: float

    # Entropy
    src_ip_entropy:   float
    periodicity_score: float = 0.0

    # DNS
    dns_query_entropy:        float = 0.0
    domain_length_mean:       float = 0.0
    domain_length_max:        float = 0.0
    subdomain_count:          float = 0.0
    dns_record_type_a_ratio:  float = 0.0
    dns_record_type_txt_ratio: float = 0.0
    dns_query_count:          int   = 0

    # TLS
    ja3_hash:        str   = ""
    ja3s_hash:       str   = ""
    tls_version:     float = 0.0
    cipher_suite_enc: int  = 0
    is_tls:          bool  = False

    # JA4
    ja4_hash:     str = ""
    ja4_hash_enc: int = 0  # pre-encoded by feature pipeline

    # QUIC
    is_quic:           bool  = False
    quic_0rtt:         bool  = False
    quic_pkt_size_mean: float = 0.0
    quic_pkt_size_std:  float = 0.0


class InferResponse(BaseModel):
    threat_class:  str
    confidence:    float
    anomaly_score: float
    severity:      str
    evidence:      list[str]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _severity(confidence: float) -> str:
    for level, threshold in SEVERITY_THRESHOLDS.items():
        if confidence >= threshold:
            return level
    return "info"


def _build_feature_vector(req: InferRequest) -> np.ndarray:
    """
    Extract model input vector from the request in FEATURE_COLUMNS order.
    Boolean columns are cast to int. Missing columns filled with 0.
    """
    row = req.model_dump()
    vector = []
    for col in FEATURE_COLUMNS:
        val = row.get(col, 0.0)
        if col in BOOL_COLUMNS:
            val = int(bool(val))
        vector.append(float(val))
    return np.array(vector, dtype=np.float32).reshape(1, -1)


async def _write_alert_to_es(req: InferRequest, result: dict) -> str:
    """Write a positive detection to Elasticsearch. Returns the document ID."""
    doc = {
        "timestamp":     datetime.fromtimestamp(req.ts, tz=timezone.utc).isoformat(),
        "flow_id":       req.flow_id,
        "src_ip":        req.src_ip,
        "dst_ip":        req.dst_ip,
        "src_port":      req.src_port,
        "dst_port":      req.dst_port,
        "protocol":      req.protocol,
        "duration":      req.duration,
        "threat_class":  result["threat_class"],
        "severity":      result["severity"],
        "confidence":    result["confidence"],
        "anomaly_score": result["anomaly_score"],
        "evidence":      result["evidence"],
        "ja3_hash":      req.ja3_hash,
        "ja4_hash":      req.ja4_hash,
        "is_quic":       req.is_quic,
        "quic_0rtt":     req.quic_0rtt,
        "kill_chain_id": None,  # filled later by correlator
    }
    resp = await state.es.index(index=ES_INDEX, document=doc)
    return resp["_id"]


def _es_alert_to_dict(hit: dict) -> dict:
    """Flatten an ES hit into the API response shape."""
    src  = hit["_source"]
    return {
        "id":            hit["_id"],
        "timestamp":     src.get("timestamp"),
        "flow_id":       src.get("flow_id"),
        "src_ip":        src.get("src_ip"),
        "dst_ip":        src.get("dst_ip"),
        "src_port":      src.get("src_port"),
        "dst_port":      src.get("dst_port"),
        "protocol":      src.get("protocol"),
        "duration":      src.get("duration"),
        "threat_class":  src.get("threat_class"),
        "severity":      src.get("severity"),
        "confidence":    src.get("confidence"),
        "anomaly_score": src.get("anomaly_score"),
        "evidence":      src.get("evidence", []),
        "kill_chain_id": src.get("kill_chain_id"),
        "ja3_hash":      src.get("ja3_hash"),
        "ja4_hash":      src.get("ja4_hash"),
        "is_quic":       src.get("is_quic"),
        "quic_0rtt":     src.get("quic_0rtt"),
    }


# ---------------------------------------------------------------------------
# POST /infer
# ---------------------------------------------------------------------------
@app.post("/infer", response_model=InferResponse)
async def infer(req: InferRequest):
    """
    Accept a feature vector, run XGBoost + Isolation Forest + SHAP,
    return classification result. Write alert to ES on positive detection.
    """
    # Build feature vector
    X = _build_feature_vector(req)

    # --- XGBoost inference ---
    probs        = state.xgb_model.predict_proba(X)[0]
    class_idx    = int(np.argmax(probs))
    confidence   = float(probs[class_idx])
    threat_class = THREAT_CLASSES[class_idx]

    # --- Isolation Forest ---
    # score_samples returns negative scores — higher = more normal
    # negate so higher anomaly_score = more anomalous (0–1 normalised approx)
    raw_score    = float(-state.iso_forest.score_samples(X)[0])
    # Clamp to 0–1 range (typical range is roughly 0.0–0.8)
    anomaly_score = float(np.clip(raw_score / 0.8, 0.0, 1.0))

    # If XGBoost confidence is below threshold, defer to anomaly detection
    if confidence < INFER_THRESHOLD:
        threat_class = "unknown_anomaly" if anomaly_score > 0.5 else "benign"

    severity = _severity(confidence)

    # --- SHAP evidence (Gowri's module) ---
    evidence: list[str] = []
    try:
        from ml.explainability import explain
        evidence = explain(req.model_dump(), threat_class)
    except ImportError:
        logger.warning("ml.explainability not available yet — evidence will be empty")
    except Exception as e:
        logger.error("SHAP explainability failed for flow_id=%s: %s", req.flow_id, e)

    result = {
        "threat_class":  threat_class,
        "confidence":    round(confidence, 4),
        "anomaly_score": round(anomaly_score, 4),
        "severity":      severity,
        "evidence":      evidence,
    }

    # --- Write to ES on positive detection ---
    if threat_class not in ("benign",):
        try:
            doc_id = await _write_alert_to_es(req, result)
            logger.info(
                "Alert written — id=%s  flow=%s  class=%s  confidence=%.3f",
                doc_id, req.flow_id, threat_class, confidence,
            )
        except Exception as e:
            logger.error("Failed to write alert to ES for flow_id=%s: %s", req.flow_id, e)

    return result


# ---------------------------------------------------------------------------
# GET /alerts
# ---------------------------------------------------------------------------
@app.get("/alerts")
async def get_alerts(
    page:         int            = Query(default=1,  ge=1),
    page_size:    int            = Query(default=20, ge=1, le=100),
    severity:     Optional[str]  = Query(default=None),
    threat_class: Optional[str]  = Query(default=None),
    src_ip:       Optional[str]  = Query(default=None),
    start_time:   Optional[str]  = Query(default=None),
    end_time:     Optional[str]  = Query(default=None),
    evidence:     Optional[str]  = Query(default=None),
):
    filters = []

    if severity:
        filters.append({"term": {"severity": severity}})
    if threat_class:
        filters.append({"term": {"threat_class": threat_class}})
    if src_ip:
        filters.append({"term": {"src_ip": src_ip}})
    if start_time or end_time:
        rng: dict = {"timestamp": {}}
        if start_time:
            rng["timestamp"]["gte"] = start_time
        if end_time:
            rng["timestamp"]["lte"] = end_time
        filters.append({"range": rng})

    # Full-text evidence search — uses ES match query (tokenised, partial match)
    must = []
    if evidence:
        must.append({"match": {"evidence": evidence}})

    query = {
        "bool": {
            "must":   must   if must   else [{"match_all": {}}],
            "filter": filters,
        }
    }

    from_idx = (page - 1) * page_size

    try:
        resp = await state.es.search(
            index=ES_INDEX,
            query=query,
            from_=from_idx,
            size=page_size,
            sort=[{"timestamp": {"order": "desc"}}],
        )
    except Exception as e:
        logger.error("ES search failed: %s", e)
        raise HTTPException(status_code=500, detail="Search failed — Elasticsearch error")

    total   = resp["hits"]["total"]["value"]
    results = [_es_alert_to_dict(h) for h in resp["hits"]["hits"]]

    return {
        "total":     total,
        "page":      page,
        "page_size": page_size,
        "pages":     max(1, (total + page_size - 1) // page_size),
        "results":   results,
    }


# ---------------------------------------------------------------------------
# GET /alerts/{id}
# ---------------------------------------------------------------------------
@app.get("/alerts/{alert_id}")
async def get_alert(alert_id: str):
    try:
        resp = await state.es.get(index=ES_INDEX, id=alert_id)
    except NotFoundError:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    except Exception as e:
        logger.error("ES get failed for id=%s: %s", alert_id, e)
        raise HTTPException(status_code=500, detail="Elasticsearch error")

    return _es_alert_to_dict(resp)


# ---------------------------------------------------------------------------
# GET /stats
# ---------------------------------------------------------------------------
@app.get("/stats")
async def get_stats(hours: int = Query(default=1, ge=1, le=24)):
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    query = {
        "bool": {
            "filter": [{"range": {"timestamp": {"gte": since}}}]
        }
    }

    aggs = {
        # Count per threat class
        "by_threat_class": {
            "terms": {"field": "threat_class", "size": 20}
        },
        # Count per severity
        "by_severity": {
            "terms": {"field": "severity", "size": 10}
        },
        # Alert volume in 5-minute buckets
        "timeline": {
            "date_histogram": {
                "field":             "timestamp",
                "fixed_interval":    "5m",
                "min_doc_count":     0,
                "extended_bounds": {
                    "min": since,
                    "max": datetime.now(timezone.utc).isoformat(),
                }
            }
        },
        # Top 10 source IPs
        "top_src_ips": {
            "terms": {"field": "src_ip", "size": 10}
        },
    }

    try:
        resp = await state.es.search(
            index=ES_INDEX,
            query=query,
            aggs=aggs,
            size=0,  # we only want aggregations, not individual hits
        )
    except Exception as e:
        logger.error("ES stats aggregation failed: %s", e)
        raise HTTPException(status_code=500, detail="Stats query failed")

    agg = resp["aggregations"]

    by_threat_class = {
        b["key"]: b["doc_count"]
        for b in agg["by_threat_class"]["buckets"]
    }
    by_severity = {
        b["key"]: b["doc_count"]
        for b in agg["by_severity"]["buckets"]
    }
    timeline = [
        {
            "bucket": b["key_as_string"],
            "count":  b["doc_count"],
        }
        for b in agg["timeline"]["buckets"]
    ]
    top_src_ips = [
        {"ip": b["key"], "count": b["doc_count"]}
        for b in agg["top_src_ips"]["buckets"]
    ]

    return {
        "total_alerts":    resp["hits"]["total"]["value"],
        "by_threat_class": by_threat_class,
        "by_severity":     by_severity,
        "timeline":        timeline,
        "top_src_ips":     top_src_ips,
    }


# ---------------------------------------------------------------------------
# GET /kill-chains
# ---------------------------------------------------------------------------
@app.get("/kill-chains")
async def get_kill_chains(hours: int = Query(default=1, ge=1, le=24)):
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    query = {
        "bool": {
            "filter": [
                {"exists": {"field": "kill_chain_id"}},
                {"range":  {"timestamp": {"gte": since}}},
            ]
        }
    }

    # Aggregate by kill_chain_id — get all alerts per chain
    aggs = {
        "chains": {
            "terms": {"field": "kill_chain_id", "size": 100},
            "aggs": {
                "stages": {
                    "top_hits": {
                        "size": 20,
                        "sort": [{"timestamp": {"order": "asc"}}],
                        "_source": [
                            "timestamp", "threat_class", "severity",
                            "confidence", "dst_ip", "dst_port",
                            "evidence", "src_ip",
                        ],
                    }
                },
                "first_seen": {"min": {"field": "timestamp"}},
                "last_seen":  {"max": {"field": "timestamp"}},
                "max_confidence": {"max": {"field": "confidence"}},
            }
        }
    }

    try:
        resp = await state.es.search(
            index=ES_INDEX,
            query=query,
            aggs=aggs,
            size=0,
        )
    except Exception as e:
        logger.error("ES kill-chains query failed: %s", e)
        raise HTTPException(status_code=500, detail="Kill-chains query failed")

    severity_order = {"critical": 4, "high": 3, "medium": 2, "info": 1}

    chains = []
    for bucket in resp["aggregations"]["chains"]["buckets"]:
        chain_id = bucket["key"]
        hits     = bucket["stages"]["hits"]["hits"]

        stages = []
        max_severity = "info"
        src_ip = None

        for hit in hits:
            s   = hit["_source"]
            sev = s.get("severity", "info")
            if severity_order.get(sev, 0) > severity_order.get(max_severity, 0):
                max_severity = sev
            if src_ip is None:
                src_ip = s.get("src_ip")
            stages.append({
                "alert_id":    hit["_id"],
                "timestamp":   s.get("timestamp"),
                "threat_class": s.get("threat_class"),
                "severity":    sev,
                "confidence":  s.get("confidence"),
                "dst_ip":      s.get("dst_ip"),
                "dst_port":    s.get("dst_port", 0),
                "evidence":    s.get("evidence", []),
            })

        chains.append({
            "chain_id":    chain_id,
            "src_ip":      src_ip,
            "first_seen":  bucket["first_seen"]["value_as_string"],
            "last_seen":   bucket["last_seen"]["value_as_string"],
            "stage_count": len(stages),
            "max_severity": max_severity,
            "stages":      stages,
        })

    # Sort chains by most recent activity first
    chains.sort(key=lambda c: c["last_seen"], reverse=True)

    return {"total": len(chains), "chains": chains}


# ---------------------------------------------------------------------------
# GET /metrics  — SSE endpoint
# ---------------------------------------------------------------------------
@app.get("/metrics")
async def get_metrics():
    """
    Server-Sent Events stream of pipeline-metrics Kafka topic.
    Jaith connects via EventSource — one persistent connection, not polling.
    """
    async def event_stream() -> AsyncGenerator[str, None]:
        consumer = AIOKafkaConsumer(
            KAFKA_TOPIC_METRICS,
            bootstrap_servers=KAFKA_BOOTSTRAP,
            auto_offset_reset="latest",     # only stream new messages, not history
            group_id=None,                  # no group — each SSE connection is independent
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            consumer_timeout_ms=1000,
        )
        try:
            await consumer.start()
            logger.info("SSE client connected to /metrics")

            # Send a heartbeat comment every second to keep the connection alive
            # even when no metrics messages are flowing
            last_heartbeat = asyncio.get_event_loop().time()

            async for msg in consumer:
                data = json.dumps(msg.value)
                yield f"data: {data}\n\n"

                # Yield control so other async tasks can run
                await asyncio.sleep(0)

                # Heartbeat every 15s — prevents proxy/browser timeout
                now = asyncio.get_event_loop().time()
                if now - last_heartbeat > 15:
                    yield ": heartbeat\n\n"
                    last_heartbeat = now

        except asyncio.CancelledError:
            logger.info("SSE client disconnected from /metrics")
        except Exception as e:
            logger.error("SSE stream error: %s", e)
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
        finally:
            await consumer.stop()

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":               "no-cache",
            "X-Accel-Buffering":           "no",    # disable nginx buffering if behind proxy
            "Access-Control-Allow-Origin": CORS_ORIGIN,
        },
    )


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    uptime = round(time.monotonic() - state.startup_time, 1)

    # Check Kafka
    kafka_status: dict = {"status": "ok", "bootstrap": KAFKA_BOOTSTRAP}
    try:
        from aiokafka.admin import AIOKafkaAdminClient
        admin = AIOKafkaAdminClient(bootstrap_servers=KAFKA_BOOTSTRAP)
        await admin.start()
        await admin.close()
    except Exception as e:
        kafka_status = {"status": "error", "detail": str(e)}

    # Check Elasticsearch
    es_status: dict = {"status": "ok", "host": f"{ES_HOST}:{ES_PORT}", "index": ES_INDEX}
    try:
        await state.es.ping()
    except Exception as e:
        es_status = {"status": "error", "detail": str(e)}

    overall = "ok" if (
        kafka_status["status"] == "ok" and
        es_status["status"]    == "ok" and
        state.model_loaded             and
        state.iso_forest_loaded
    ) else "degraded"

    return {
        "status":                 overall,
        "uptime_seconds":         uptime,
        "model_loaded":           state.model_loaded,
        "isolation_forest_loaded": state.iso_forest_loaded,
        "kafka":                  kafka_status,
        "elasticsearch":          es_status,
    }


# ---------------------------------------------------------------------------
# Correlator background loop (imported here to avoid circular imports)
# ---------------------------------------------------------------------------
async def _correlator_loop():
    """
    Imported from api/correlator.py and run as a background task.
    Defined here as a thin wrapper — actual logic lives in correlator.py.
    """
    try:
        from api.correlator import run_correlator
        await run_correlator(state.es, ES_INDEX)
    except ImportError:
        logger.warning("api/correlator.py not found — kill-chain correlation disabled")
    except asyncio.CancelledError:
        raise
    except Exception as e:
        logger.exception("Correlator crashed: %s", e)