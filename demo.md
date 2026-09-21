# Aegis — Live Demo Runbook

**The plan:** bring up the isolated Docker lab (attacker + victim + Zeek +
Kafka + Elasticsearch), run an attack script from the attacker container
against the victim, capture it and process it through Zeek in the few
seconds right after, and watch the alert appear in the React dashboard
end to end — no pre-recorded PCAPs prepared ahead of time, everything
generated fresh in front of the audience.

**Important — verified 2026-09-17:** Zeek's own container is **not**
in-path on the Docker bridge network (`labnet` is a plain Linux bridge —
a switch, not a hub), so `zeek -i eth0` running inside the `zeek`
container never sees attacker↔victim traffic; it only sees its own.
Testing this end-to-end confirmed `conn.log` stays empty no matter what
attack you run against the victim while Zeek listens on its own
interface. **The workflow that actually works — and the one below —
captures with `tcpdump` on the victim container instead, then feeds that
pcap through Zeek offline, writing straight into `zeek/logs/`.** Because
that's the same directory Terminal 3's watcher is already monitoring,
the rest of the pipeline (feature pipeline → Kafka → FastAPI/ML →
Elasticsearch → dashboard) still reacts within a few seconds, exactly
like a true live capture would — the only difference the audience will
never notice is that Zeek processes the pcap instead of sniffing the
wire directly. This is also what `README.md`'s own validated lab
workflow describes, and matches the change already reflected in
`zeek/scripts/main.zeek`'s usage comment.

**Yes, the pipeline itself works** — the whole downstream chain (Zeek →
feature pipeline → Kafka → FastAPI/ML → Elasticsearch → dashboard) is
solid; the above is purely about *how traffic gets in front of Zeek*.
The trained models (`ml/model.joblib`, `ml/iso_forest.joblib`, etc.) are
already committed, so no retraining is needed the day of.

**Fast path — `./start_demo.sh` and `./run_attack.sh`:** everything in
sections 0–1 below (bring up Docker, wait for Kafka/ES, create the ES
index, start tcpdump, start the watcher/producer/consumer/API/dashboard,
all via `.venv`) is automated by `./start_demo.sh` at the repo root
(`./start_demo.sh --clean` also wipes stale logs/alerts first). Once it
prints "Aegis is up", run an attack with `./run_attack.sh <script>
[args...]` — e.g. `./run_attack.sh port_scan.py --profile
fast_sequential` — which fires the attack in the right container *and*
runs the `zeek -C -r` processing step for you. `./stop_demo.sh` shuts
everything down (`--down` also tears down the Docker lab). The manual
step-by-step walkthrough below is still here for when you want to narrate
what's happening in each terminal, or if something needs debugging.

---

## 0. Do this the night before (not day-of)

Docker image builds and `npm install` are slow the first time — don't burn
presentation time on them.

**Every command below that invokes `python3`, `pip`, or `uvicorn` assumes
the repo's `.venv` is active** — run `source .venv/bin/activate` first in
every new terminal before any of them (Terminals 3, 4, 5 in the startup
sequence below, plus every `pip`/`pytest` command in this section).
**Verified 2026-09-18: without this, `python3`/`uvicorn` on this machine
silently resolve to a system/user Python 3.14 install with different,
unpinned package versions** (newer scikit-learn, newer uvicorn, etc.) —
it happened to still work when tested, but it's not the environment
these fixes were validated against, and `requirements.txt` itself warns
that Python 3.14 lacks prebuilt wheels for some packages. Don't gamble
on it during the actual demo.

1. **Pull in today's bug fixes.** If you haven't already, make sure your
   Python environment matches `requirements.txt` — it now uses
   `confluent-kafka` instead of `kafka-python`. If `kafka-python` is
   installed anywhere on your PATH's Python, **uninstall it**:
   ```bash
   source .venv/bin/activate
   pip uninstall -y kafka-python
   pip install -r requirements.txt
   ```
   (`kafka-python`'s own `kafka/` package name collides with this project's
   `kafka/` folder and silently breaks the producer/consumer — this bit us
   during today's review, so check it now, not tomorrow. `requirements.txt`
   also picked up `aiohttp` and `cramjam` today — both required for the
   API/dashboard to actually work; see the troubleshooting table if you
   see errors mentioning either.)

2. **Build the lab images once:**
   ```bash
   cd Aegis
   make up          # docker compose up -d --build
   make status      # confirm attacker, victim, benign, zeek, kafka,
                     # zookeeper, elasticsearch, kafka-init are all Up
   ```

3. **Create the Elasticsearch index** (safe to re-run; no-ops if it already has the right mapping, and recreates it if it was auto-created with the wrong one):
   ```bash
   python3 es/init_index.py
   ```

4. **Install dashboard dependencies:**
   ```bash
   cd dashboard && npm install && cd ..
   ```

5. **Sanity-check the models load** (optional but reassuring):
   ```bash
   python3 -m ml.check_model
   ```

6. **Confirm the victim container's interface** (this is what `tcpdump`
   captures on, and what Zeek's offline processing assumes). Inside
   Docker it's almost always `eth0`, but verify once — neither the
   `victim` nor `zeek` image ships the `ip` command, so use:
   ```bash
   docker exec victim ls /sys/class/net
   ```
   Note the interface name — you'll use it in Terminal 2 of the startup
   sequence below. If it isn't `eth0`, swap it in every command that
   references `eth0` (including the `tcpdump -i eth0` and `zeek -C -r`
   commands).

7. **Leave the containers running overnight is fine** (`docker compose
   down -v` deletes state — don't run that until the demo is over). If you
   do stop them, `make up` again tomorrow just restarts, no rebuild.

   **If the machine reboots or sleeps overnight** (containers get killed
   uncleanly instead of stopped gracefully), Kafka can fail to come back
   up the first time with `NodeExistsException` in `docker logs kafka` —
   ZooKeeper still holds the previous, not-yet-expired ephemeral broker
   registration. Verified fix: just retry once, ~15–20s later —
   `docker compose up -d kafka` — it comes up clean once ZooKeeper's
   session timeout expires. `make status` / `make health` should confirm
   it either way before you move on.

8. **Clear out any stale logs/data from previous test runs** so the demo
   starts from a clean slate and old alerts don't confuse the audience.
   Zeek writes `zeek/logs/*.log` as root inside the container, so a plain
   host-side `rm` fails with `Permission denied` — delete them via
   `docker exec` instead. **Also stop the Kafka consumer first and reset
   its offset** — verified 2026-09-18: deleting Elasticsearch alerts
   does *not* touch the Kafka topic itself, so any not-yet-consumed
   backlog from earlier rehearsals sits in `raw-features` and silently
   replays as "new" alerts the instant you start the consumer again,
   making it look like duplication/corruption came back when it's really
   just old messages catching up:
   ```bash
   # make sure terminal 4 (kafka.consumer) is stopped before this
   docker exec zeek sh -c 'rm -f /zeek/logs/*.log'
   rm -f data/features/live_*.parquet
   docker exec victim sh -c 'rm -f /pcaps/capture*.pcap /pcaps/attack_*.pcap'
   curl -s -X POST "http://localhost:9200/alerts/_delete_by_query" \
     -H 'Content-Type: application/json' \
     -d '{"query": {"match_all": {}}}' | head -c 200
   docker exec kafka kafka-consumer-groups --bootstrap-server localhost:9092 \
     --group aegis-consumer --topic raw-features \
     --reset-offsets --to-latest --execute
   ```
   (`./start_demo.sh --clean` does all of this for you, including the
   Kafka reset.)

---

## 1. Day-of startup sequence

Open **6 terminal tabs/panes** at the repo root (`Aegis/`). Keep them all
visible if you can — watching the Kafka consumer print inference results
live while Zeek writes `conn.log` lines is genuinely good demo material.

### Terminal 1 — infra (if not already up from last night)
```bash
make up
make status        # everything should say "Up"
```

### Terminal 2 — tcpdump on the victim (restart fresh before every act)
```bash
docker exec -it victim tcpdump -i eth0 -U -w /pcaps/capture_01.pcap
```
`-U` flushes to disk after every packet, so the file is always complete
the moment the attack script finishes — no need to stop cleanly for the
data to be usable. This blocks in the foreground.

**Important — verified 2026-09-18: use a fresh `-w` filename before
every single act, don't let one file accumulate across attacks.** By
default, Zeek assigns each flow a UID from a random seed, and that seed
is freshly randomized on every separate `zeek -C -r` invocation — so
reprocessing the identical pcap twice gives two completely different
sets of UIDs for the same flows. If you let `capture.pcap` accumulate
and reprocess the whole thing each time, every old flow gets a
brand-new random `flow_id` on every run and sails straight past the
watcher's dedup — so every act silently re-floods the whole pipeline
with every previous act's traffic relabeled as "new". Symptoms: alert
counts balloon into the thousands, and each new act takes longer and
longer to actually show up (a growing duplicate backlog ahead of it in
Kafka). Before each act: Ctrl+C this terminal, bump the filename
(`capture_02.pcap`, `capture_03.pcap`, ...), and restart it. (This is
exactly what `./run_attack.sh` automates for you — see the fast path
note above.)

**Don't try to "fix" this with Zeek's `-D` flag instead** (deterministic
seeds) — that was tried and reverted. `-D` doesn't key UIDs off the
actual packet content, it just resets Zeek's UID counter to the same
starting state every run, so two genuinely *different* attacks with the
same flow count (e.g. two separate `syn_flood` runs) get assigned the
exact same UIDs despite completely different traffic — which makes the
watcher's dedup silently swallow the second attack's real alerts instead
of only catching true duplicates. A fresh pcap per act, never
reprocessed, is the only fix that's actually correct here.

(Why tcpdump instead of Zeek listening live: see the note at the top of
this file — Zeek's own container isn't in-path on the Docker bridge, so
it never sees attacker↔victim traffic directly.)

> If you'd rather see visible activity here, open an extra terminal and
> run `tail -f zeek/logs/conn.log` on the host instead — new lines will
> appear each time you process a capture through Zeek (step 2 below).

### Terminal 3 — feature watcher + Kafka producer
```bash
source .venv/bin/activate
python3 run_pipeline.py
```
Watches `./zeek/logs`, runs the feature pipeline whenever Zeek's logs
settle, and streams `FeatureRow`s onto the `raw-features` Kafka topic.
You'll see `watcher` log lines here once Zeek starts producing `conn.log`.

### Terminal 4 — Kafka consumer (calls `/infer`, writes alerts)
```bash
source .venv/bin/activate
python3 -m kafka.consumer
```
This is the terminal to watch during the live attack — it prints
`flow_id=... threat_class=... confidence=...` for every flow it scores.

### Terminal 5 — FastAPI backend
```bash
source .venv/bin/activate
uvicorn api.main:app --host 0.0.0.0 --port 8000
```
Wait for `Aegis API ready` in the log before moving on — it loads the
XGBoost model, Isolation Forest, and connects to Elasticsearch at startup,
and refuses to start if any of those fail.

### Terminal 6 — dashboard
```bash
cd dashboard
npm run dev
```
Open **http://localhost:5173** in a browser. The dashboard's Vite dev
server proxies `/alerts`, `/stats`, `/metrics`, `/kill-chains`, `/health`
to `localhost:8000` automatically — no extra config needed.

Check the **top status bar** first: it should show `SYSTEM: OK`, `KAFKA:
OK`, `ES: OK`. If it says `OFFLINE`, something in terminals 1/4/5 isn't up
yet — fix that before continuing (see Troubleshooting below).

---

## 2. The live attack demo

Open a **7th terminal** to drive the attack from inside the attacker
container. Everything below defaults to targeting the victim
(`10.10.0.3`) automatically — no IP addresses to type live.

```bash
docker exec -it attacker bash
cd /scripts
```

**The pattern for every act below is three steps:**
1. In Terminal 2: Ctrl+C the current `tcpdump`, restart it with a new
   `-w` filename (e.g. `capture_02.pcap` for the second act). This is
   not optional — see the note above.
2. Run the attack script (it sends real packets from the attacker
   container — Terminal 2's freshly-restarted `tcpdump` is capturing
   them as they go).
3. Feed *that act's* capture through Zeek, writing straight into the
   directory Terminal 3 is already watching — this is what actually
   makes the alert appear, since Zeek can't see the traffic on its own:
   ```bash
   docker exec zeek zeek -C -r /pcaps/capture_02.pcap /zeek/site/main.zeek Log::default_logdir=/zeek/logs
   ```
   (Run this from your host terminal, not inside the attacker container
   — and use the same filename you gave `tcpdump` in step 1.)

### Recommended opening act — port scan (fast, ~1 second, unmistakable)
```bash
python3 port_scan.py --profile fast_sequential
```
Scans ports 1–1024 on the victim in about a second. Then, from your host
terminal, run the `zeek -C -r` command above (against this act's capture
file). Within a few seconds you should see a `port_scan` alert land in
the **Live Feed** (http://localhost:5173), and the Kafka consumer
terminal will print the matching `threat_class=port_scan` line.

### Second act — SYN flood (visible on the Metrics page)
Restart Terminal 2's `tcpdump` with a new filename first
(`capture_02.pcap`), then:
```bash
python3 syn_flood.py --profile low_steady
```
Sends for ~20 seconds at 50 packets/sec. Then run `zeek -C -r` against
`capture_02.pcap`. Switch to the **Metrics** tab before that finishes
processing — `FLOWS/SEC` and `PIPELINE LATENCY` will visibly spike, and
a `ddos` alert should appear in the Live Feed.

### Optional third act — exfiltration (shows the Kill Chains page)
Restart Terminal 2's `tcpdump` with a new filename again
(`capture_03.pcap`), then:
```bash
python3 exfiltration.py --flows 5 --send-live --output /pcaps/exfiltration_candidate.pcap
```
(That `--output` is the script's own offline archival copy, unrelated to
Terminal 2's capture — it's a different filename, so it's fine.) Then
run `zeek -C -r` against `capture_03.pcap`. **Use `exfiltration.py`
here, not
`c2_beacon.py`** — `c2_beacon.py` (and `dga.py`/`dns_tunnel.py`) are
synthetic *dataset generators* only: they write a PCAP but never
transmit, and `c2_beacon.py` also hardcodes an unrelated source IP
(`10.0.0.10`) that doesn't match the lab's `10.10.0.0/24` network, so it
can't correlate with anything even if it did send. `exfiltration.py` was
missing the same live-send step; it's been fixed to send with
`--send-live` and already uses the attacker's real IP by default, so it
pairs correctly with the port scan.

`--flows 5` takes about 30–60s to send (it's a mix of burst profiles);
watch for it to finish before running `zeek -C -r` against
`capture_03.pcap`. Since port_scan (`port_scan`) and this
(`exfiltration`) are two distinct non-benign threat classes both from
`10.10.0.2` within the 10-minute lookback window, they should get
correlated into a single kill chain (`GET /kill-chains`) within ~30s
(the correlator's poll interval).

### If you want a "before" baseline shown first
Restart Terminal 2's `tcpdump` with a new filename first
(`capture_00.pcap` — this one's meant to run *before* the attacks), then
from the benign container, in its own terminal:
```bash
docker exec -it benign bash
cd /scripts
python3 benign_traffic.py --flows 50 --send-live
```
`--send-live` is required — without it the script only writes a PCAP for
offline dataset use and nothing reaches the wire. Takes about 60–90s to
send at `--flows 50` (it also fixed a bug where it briefly appeared to
hang with `WARNING: MAC address to reach destination not found` — see
the troubleshooting table if you still see that). With it, this
generates ordinary-looking traffic the audience can watch in a quiet
Live Feed before you kick off the attack scripts — good narrative
contrast. Same capture-then-process step as the attacks: run `zeek -C -r`
against `capture_00.pcap` to see it land as `benign` entries. Then
restart Terminal 2 with `capture_01.pcap` before the port scan act.

---

## 3. What to point out on screen

- **Live Feed** (`/`): the alert row appearing in real time, with
  `src_ip`/`dst_ip`, confidence bar, and severity badge.
- Click a row to open the **side panel** → SHAP evidence strings (e.g.
  "Many destination ports contacted (supports prediction)").
- **Metrics** (`/metrics`): live SSE-driven flows/sec, throughput, Kafka
  queue depth, and latency — this is the operational-telemetry story.
- **Stats** (`/stats`): threat-class distribution and the alert-volume
  timeline filling in after a few scenarios.
- **Kill Chains** (`/kill-chains`): if you ran two different attack classes
  from the attacker IP within the lookback window, show the correlated
  multi-stage chain.
- **Status bar** (top of every page): `KAFKA: OK`, `ES: OK` — a nice
  "everything's alive" glance for judges who ask about the architecture.

---

## 4. If something breaks

| Symptom | Likely cause | Fix |
|---|---|---|
| Status bar says `OFFLINE` | FastAPI (terminal 5) isn't up, or ES/Kafka aren't reachable | Check terminal 5's log for the startup error; confirm `make status` shows all containers `Up` |
| No alerts ever appear, but consumer terminal is quiet too | You forgot the `zeek -C -r ...` processing step after the attack, or `tcpdump` wasn't actually running/capturing in Terminal 2 | Confirm Terminal 2's `tcpdump` is running and its pcap file for this act is growing (`docker exec victim ls -la /pcaps/capture_NN.pcap`); then run `zeek -C -r` against that same file |
| Alert counts balloon into the thousands, and each new act takes longer and longer to show up | Reused the same `capture.pcap` across multiple acts instead of restarting `tcpdump` with a fresh filename each time — Zeek's non-deterministic UIDs mean every old flow gets re-emitted as "new" on every reprocess (see the note in section 1, Terminal 2) | `./run_attack.sh` already does this correctly (fresh file per attack). Doing it manually: always Ctrl+C Terminal 2 and restart with a new `-w` filename before each act — never reprocess an old capture file that's already produced alerts |
| Alert counts keep climbing on their own for a while after an attack, or old-looking alerts reappear after you've already cleared Elasticsearch | Stale, not-yet-consumed backlog sitting in the Kafka `raw-features` topic from earlier rehearsals/testing — deleting ES alerts doesn't touch Kafka, so the backlog replays the moment the consumer runs (verified 2026-09-18; can take 30–90s+ to drain since each message needs a real `/infer` call at ~50–100ms) | Reset the consumer group's offset before the demo (see step 0.8) — `./start_demo.sh --clean` does this automatically. If it's mid-drain, just wait; check `docker exec kafka kafka-consumer-groups --bootstrap-server localhost:9092 --describe --group aegis-consumer` for `LAG` |
| Dashboard behaves erratically / alerts seem duplicated in a way nothing here explains | You may have run `./start_demo.sh` twice without `./stop_demo.sh` in between, leaving two `kafka.consumer` (or two of anything) fighting over the same consumer group | Fixed 2026-09-18 — `start_demo.sh` now stops any leftover services from a previous run before starting new ones. If you're on an older copy, check `ps aux \| grep -E "run_pipeline\|kafka.consumer\|uvicorn\|vite"` for duplicates and kill the extras |
| `docker exec zeek ip -brief addr` fails with `exec: "ip": not found` | The zeek image doesn't ship `iproute2` | Use `docker exec zeek cat /proc/net/dev` or `docker exec zeek ls /sys/class/net` instead to confirm the interface name is `eth0` |
| Consumer prints `Cannot reach FastAPI` | Terminal 5 crashed or isn't started yet | Restart `uvicorn api.main:app --port 8000` |
| `ModuleNotFoundError: confluent_kafka` (or similar) | Dependencies not installed, or `kafka-python` is still shadowing the local `kafka/` package | `pip uninstall -y kafka-python && pip install -r requirements.txt` |
| FastAPI fails at startup with `Model file missing: ../ml/model.joblib` | Fixed 2026-09-17 — `api/main.py` used a path relative to cwd instead of the repo root | Should no longer happen; if it does, confirm you're on the current `api/main.py` and re-run `pip install -r requirements.txt` |
| FastAPI fails at startup with `ValueError: You must have 'aiohttp' installed` | `aiohttp` is required by the async Elasticsearch client but wasn't in `requirements.txt` | Fixed — now pinned in `requirements.txt`. If you hit this, `pip install -r requirements.txt` again |
| Metrics page (SSE) logs `SSE stream error: UnsupportedCodecError: Libraries for lz4 compression codec not found` | `aiokafka` needs `cramjam` to decompress the lz4-compressed metrics topic (installing the `lz4` PyPI package does **not** fix this — aiokafka 0.11 uses `cramjam`) | Fixed — `cramjam` is now pinned in `requirements.txt`. If you hit this, `pip install -r requirements.txt` again and restart the API |
| Dashboard Stats / Kill Chains pages show "Connection Error — Unable to reach API" (the API returns HTTP 500 with an ES `Fielddata is disabled on [threat_class]` error in `logs/run/api.log`) | The `alerts` index was auto-created by Elasticsearch with text-typed fields (the ES container has no persistent volume, so the index disappears when the container is recreated, and a write that arrives first recreates it with the wrong mapping) | Fixed 2026-09-21 — the API now checks the mapping at startup and recreates the index if it's wrong, and `es/init_index.py` does the same. Just restart the API (or run `python3 es/init_index.py`); existing alerts in a wrong-mapped index are dropped |
| Everything alerts `unknown_anomaly` at low severity | Isolation Forest / model files missing or stale | Confirm `ml/model.joblib`, `ml/iso_forest.joblib`, `ml/label_encoder.joblib`, `ml/encoders.joblib` all exist |
| Dashboard shows nothing and never errors either | Browser hit `localhost:5173` but Vite proxy target (`localhost:8000`) isn't up | Same as the FastAPI row above |
| Old alerts from a previous test run are cluttering the feed | Didn't clear Elasticsearch / `zeek/logs` beforehand | Re-run the cleanup commands in step 0.8 |
| `syn_flood.py`/`udp_flood.py`/`exfiltration.py --send-live` raise `PermissionError` or send nothing | Missing `NET_RAW`/`NET_ADMIN` capability, or `scapy` can't resolve a route to the target | Confirm you're running inside the `attacker` container (`docker exec -it attacker bash`), not on the host |
| `docker logs kafka` shows `NodeExistsException` and the container keeps exiting right after `make up` | ZooKeeper still holds the previous session's ephemeral broker registration — happens after an unclean shutdown (machine reboot/sleep) | Wait ~15–20s, then `docker compose up -d kafka` once more — it comes up clean once ZooKeeper's old session times out |
| First attack works, then every attack after it produces nothing new (or shows the same stale `c2_beaconing`/`10.0.0.10` alerts repeating) | Something wrote to the shared capture file with `wrpcap` (e.g. a dataset-only script's `--output` pointed at the same `/pcaps/*.pcap` tcpdump had open), truncating it out from under tcpdump and corrupting it — every `zeek -C -r` since has been re-reading that broken snapshot | `./run_attack.sh` refuses any `--output` under `/pcaps/` now (see its guard), but to recover manually: kill tcpdump on the victim, restart it with a brand-new `-w` filename, then run a real attack again. **Never point any attack script's `--output` at the file tcpdump is currently writing to** |
| `benign_traffic.py --send-live` prints `WARNING: MAC address to reach destination not found. Using broadcast.` and seems to hang | Fixed 2026-09-18 — half its packets simulate the victim's *replies* by addressing them to the benign container's own IP; scapy can't ARP-resolve a destination that's your own address and retries/times out per packet. It now only transmits the genuine outbound half live | Should no longer happen (`--flows 50` now takes ~60–90s, not indefinitely); if you still see it, confirm you're on the current `benign/scripts/benign_traffic.py` |

---

## 5. Shutdown (after the demo)

```bash
# Ctrl+C each of terminals 2–6 (tcpdump, watcher/producer, consumer, API, dashboard)
make down          # docker compose down -v — stops and removes containers/volumes
```
