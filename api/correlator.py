"""
Background task that runs every 30 seconds.

Logic:
  1. Query ES for all alerts in the last 10 minutes
  2. Group by src_ip
  3. For each src_ip with 2+ different threat_class values
     → assign a shared kill_chain_id (UUID)
     → update those ES documents via bulk update API
  4. Log any newly created kill chains

This runs inside the FastAPI lifespan as an asyncio task.
It is called from api/main.py — do not run this file directly.
"""

import asyncio
import logging
import uuid
from datetime import datetime, timezone, timedelta

from elasticsearch import AsyncElasticsearch

logger = logging.getLogger("api.correlator")

CORRELATOR_INTERVAL_SECONDS = 30
LOOKBACK_MINUTES            = 10

# ---------------------------------------------------------------------------
# Main correlator loop — called from main.py lifespan
# ---------------------------------------------------------------------------
async def run_correlator(es: AsyncElasticsearch, index: str):
    """
    Runs forever until cancelled. Calls _correlate() every 30 seconds.
    """
    logger.info(
        "Correlator started — interval: %ds, lookback: %dm",
        CORRELATOR_INTERVAL_SECONDS,
        LOOKBACK_MINUTES,
    )
    while True:
        try:
            await _correlate(es, index)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            # Log and keep running — one bad cycle shouldn't stop correlation
            logger.error("Correlator cycle failed: %s", e)

        await asyncio.sleep(CORRELATOR_INTERVAL_SECONDS)


# ---------------------------------------------------------------------------
# One correlation cycle
# ---------------------------------------------------------------------------
async def _correlate(es: AsyncElasticsearch, index: str):
    since = (datetime.now(timezone.utc) - timedelta(minutes=LOOKBACK_MINUTES)).isoformat()

    # -------------------------------------------------------------------------
    # Step 1 — Fetch alerts ingested in the last 10 minutes
    # -------------------------------------------------------------------------
    query = {
        "bool": {
            "filter": [
                {"range": {"ingested_at": {"gte": since}}},
                # Exclude benign — only real detections participate in chains
                {"bool": {"must_not": [{"term": {"threat_class": "benign"}}]}},
            ]
        }
    }

    try:
        resp = await es.search(
            index=index,
            query=query,
            size=1000,   # max alerts to consider per cycle — enough for SIH scale
            _source=["src_ip", "threat_class", "kill_chain_id", "timestamp", "ingested_at"],
            sort=[{"ingested_at": {"order": "asc"}}],
        )
    except Exception as e:
        logger.error("Correlator ES query failed: %s", e)
        return

    hits = resp["hits"]["hits"]
    if not hits:
        logger.debug("Correlator: no alerts in last %d minutes", LOOKBACK_MINUTES)
        return

    # -------------------------------------------------------------------------
    # Step 2 — Group by src_ip
    # -------------------------------------------------------------------------
    # Structure: { src_ip: [ {id, threat_class, kill_chain_id}, ... ] }
    by_src: dict[str, list[dict]] = {}

    for hit in hits:
        src = hit["_source"]
        ip  = src.get("src_ip")
        if not ip:
            continue
        by_src.setdefault(ip, []).append({
            "id":            hit["_id"],
            "threat_class":  src.get("threat_class"),
            "kill_chain_id": src.get("kill_chain_id"),
            "timestamp":     src.get("timestamp"),
            "ingested_at":    src.get("ingested_at"),
        })

    # -------------------------------------------------------------------------
    # Step 3 — For each src_ip with 2+ different threat classes
    #          assign or reuse a kill_chain_id and bulk update ES
    # -------------------------------------------------------------------------
    new_chains     = 0
    extended_chains = 0
    bulk_ops: list[dict] = []

    for src_ip, alerts in by_src.items():
        threat_classes = {a["threat_class"] for a in alerts}

        # Only correlate if this source triggered 2+ distinct threat classes
        if len(threat_classes) < 2:
            continue

        # Check if any alert already has a kill_chain_id
        existing_chain_id = next(
            (a["kill_chain_id"] for a in alerts if a["kill_chain_id"]),
            None,
        )

        if existing_chain_id:
            chain_id = existing_chain_id
            # Check if any alerts in this group don't have the chain ID yet
            untagged = [a for a in alerts if not a["kill_chain_id"]]
            if not untagged:
                continue  # all already tagged — nothing to do
            extended_chains += 1
            logger.info(
                "Extending kill chain %s for src_ip=%s — adding %d alert(s) | classes: %s",
                chain_id, src_ip, len(untagged), sorted(threat_classes),
            )
        else:
            # New kill chain — generate a UUID
            chain_id  = f"kc-{uuid.uuid4()}"
            untagged  = alerts  # tag all of them
            new_chains += 1
            logger.info(
                "New kill chain detected — id=%s  src_ip=%s  classes=%s  alerts=%d",
                chain_id, src_ip, sorted(threat_classes), len(alerts),
            )

        # Build bulk update operations for untagged alerts
        for alert in untagged:
            # ES bulk format: action line followed by data line
            bulk_ops.append({"update": {"_index": index, "_id": alert["id"]}})
            bulk_ops.append({"doc": {"kill_chain_id": chain_id}})

    # -------------------------------------------------------------------------
    # Step 4 — Execute bulk update
    # -------------------------------------------------------------------------
    if not bulk_ops:
        logger.debug("Correlator: no updates needed this cycle")
        return

    try:
        bulk_resp = await es.bulk(operations=bulk_ops, refresh=True)

        # Count errors in bulk response
        errors = [
            item for item in bulk_resp.get("items", [])
            if item.get("update", {}).get("error")
        ]
        if errors:
            logger.error(
                "Bulk update had %d error(s): %s",
                len(errors),
                errors[:3],  # log first 3 only
            )

        updated = len(bulk_ops) // 2  # each update is 2 lines
        logger.info(
            "Correlator cycle complete — new chains: %d | extended: %d | alerts updated: %d",
            new_chains, extended_chains, updated,
        )

    except Exception as e:
        logger.error("Correlator bulk update failed: %s", e)