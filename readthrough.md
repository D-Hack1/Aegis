# Aegis — Explain-It-To-A-Judge Guide

This is the plain-English version. Use it to talk through the project
without getting lost in code — the technical detail lives in
`README.md` and `demo.md`.

---

## 1. What problem are we solving?

When an attacker probes or attacks a network — scanning ports, flooding
it with traffic, quietly stealing data — that activity leaves traces in
the raw network traffic. The traditional way to catch this is to write
manual rules ("if you see 1000 connections from one IP in 1 second,
that's a port scan") and stare at logs.

**Aegis watches network traffic and tells you, automatically and in
real time, what kind of attack is happening, how confident it is, and
why it thinks so** — without a human writing rules for every attack
pattern in advance.

It's built for **Smart India Hackathon 2026, Problem Statement 145**,
and it runs entirely passively: it only *observes* traffic, it never
sits in the middle of the network or blocks anything. That matters
because a monitoring tool that can crash or misbehave shouldn't be able
to take the network down with it.

---

## 2. The one-sentence pitch

**"We turn raw network packets into labeled, explained security alerts,
in seconds, using machine learning — and we can show you the whole
pipeline working live, right now, against a real (safely sandboxed)
attack."**

---

## 3. The pipeline, in plain terms

Think of it as six stations on a conveyor belt. Traffic goes in one end,
a labeled alert comes out the other end, a few seconds later.

```
 1. Traffic          2. Zeek              3. Feature          4. Kafka
    happens     -->     reads it     -->     Pipeline    -->   (the
    on the              and writes           turns it          conveyor
    network             structured           into numbers      belt)
                        logs                 a model can
                                              understand

 5. ML Model          6. Dashboard
    scores it    -->     shows you
    + explains            the alert,
    why                   live
```

**Station 1 — Traffic.** In our demo lab, this is a Docker network with
an "attacker" container and a "victim" container. In a real deployment
it would be a tap on a real network link.

**Station 2 — Zeek.** Zeek is a widely-used, open-source network
security monitor (not something we wrote). It doesn't detect
attacks itself — it just turns raw packets into structured, readable
logs: "this IP talked to that IP on this port for this long and sent
this many bytes." Think of it as the difference between a security
camera's raw footage and a timestamped log of "who entered which door
when."

**Station 3 — Feature Pipeline (our code).** A single network
connection isn't very informative on its own. This step looks at *how
many* connections a source IP made, *how many different ports/hosts* it
touched, *how regular* the timing is, whether TLS fingerprints look
unusual, etc. — turning Zeek's logs into a row of ~30 numbers ("features")
per network flow, which is what a machine learning model can actually
read.

**Station 4 — Kafka.** A message queue (industry-standard, e.g. used at
LinkedIn, Uber, Netflix) that sits between "features are ready" and
"go score them." This is what makes the system *streaming*: features
flow in continuously, get queued, and get processed as fast as the
model can keep up — so the pipeline doesn't fall over if traffic spikes.

**Station 5 — the ML model.** Two models work together:
- **XGBoost** (a well-known, tree-based classifier) answers: *"which of
  these seven known attack types does this flow look like?"* —
  `port_scan`, `ddos`, `c2_beaconing`, `dns_anomaly`, `exfiltration`,
  `malware_tls`, or `benign`.
- **Isolation Forest** (an anomaly detector) answers a different
  question: *"does this flow look weird at all, even compared to attack
  types we've seen before?"* — this is what would catch something novel
  that the classifier was never trained on.
- **SHAP** (an explainability library) then answers *"why did the model
  decide that?"* — it turns the model's internal math into sentences
  like *"Many destination ports contacted (supports prediction)"*, so an
  analyst isn't just told "trust me," they're shown the evidence.

**Station 6 — the dashboard.** A React web app that shows:
- **Live Feed** — alerts appearing in real time as they're scored.
- **Metrics** — operational health: how many flows/sec, how much data,
  how long inference is taking (SRE-style dashboard, not security
  content).
- **Stats** — how many alerts of each type, over time.
- **Kill Chains** — if the *same* attacker IP triggers two *different*
  attack types within a short window (say, a port scan followed by data
  exfiltration), we automatically link them into one "kill chain" —
  the story of a multi-step attack, not just a pile of disconnected
  alerts.

---

## 4. Why this design, not something simpler?

A judge might ask: *"why not just write detection rules directly, why
all this ML/Kafka machinery?"* Good answers:

- **Rules don't generalize.** A rule tuned for "1000 SYN packets/sec"
  breaks the moment an attacker slows down or spreads across more
  source IPs. A model trained on the *shape* of the behavior (fan-out,
  timing regularity, entropy) generalizes better and can also flag
  anomalies it's never explicitly seen (that's the Isolation Forest's
  job).
- **Streaming (Kafka) means it scales.** Feature extraction, scoring,
  and storage are decoupled — you could point this at a much busier
  network and the pieces would just process their queue faster/slower
  independently, instead of one big script falling over.
- **Explainability isn't optional in security.** An analyst won't act on
  a black-box "97% malicious" score. SHAP evidence strings are what let
  a human actually verify and trust an alert.
- **Kill-chain correlation turns noise into a story.** Ten isolated
  alerts are hard to act on. "This one IP did a port scan, then started
  exfiltrating data, ten minutes later" is something a SOC analyst can
  actually respond to.

---

## 5. What's real vs. what's simulated, and why that's fine

Be upfront about this if asked — it's a strength, not a weakness, in a
hackathon context:

- The **attacker/victim/benign network** is a real, isolated Docker
  network — not pre-recorded data. When we run an attack script, real
  packets really go out over a real (sandboxed) network interface.
- **Zeek genuinely processes that real traffic** and produces real
  `conn.log`/`dns.log` output — nothing about the telemetry is faked.
- The one adaptation: Zeek's own container can't sit "in the path" of
  the attacker↔victim traffic on this particular Docker network setup
  (a technical detail: the network is a switch, not a hub, so only two
  ends of a connection see each other's packets — Zeek's own interface
  is a third, uninvolved party). So instead of Zeek sniffing the wire
  directly, we capture with `tcpdump` on the victim (which *is* one of
  the two ends, so it does see everything) and feed that capture through
  Zeek within seconds — same tool, same processing, same output, just a
  one-hop detour to get the packets to it. The audience will not be able
  to tell the difference: an attack still goes from "not yet run" to
  "alert on screen" in a few seconds, live, with a script chosen at
  demo time, not pre-baked.
- **The ML models are pre-trained and committed to the repo** —
  training happens ahead of time on synthetic-but-realistic labeled
  traffic for all seven classes; the demo runs *inference*, not
  training, which is exactly how a real deployment would work (you
  don't retrain a security model live).

---

## 6. Anticipated judge questions (and short answers)

**"Is this actually machine learning, or just if/else rules dressed up?"**
XGBoost and Isolation Forest are trained on labeled and unlabeled
traffic respectively — the classification boundaries come from the
training data, not hand-written thresholds. We can show the confusion
matrix / classification report from training if asked.

**"What happens with an attack type you've never trained on?"**
That's exactly what the Isolation Forest half of the system is for — it
flags flows that look anomalous even if the classifier doesn't
recognize the specific pattern, rather than silently calling everything
"benign."

**"Could this scale to a real enterprise network?"**
The architecture already reflects that: Kafka decouples ingestion from
inference so throughput isn't bottlenecked by a single process, and
Elasticsearch is a proven horizontally-scalable store for exactly this
kind of time-series security event data.

**"What's the actual output an analyst would use?"**
An alert with: source/destination IP and port, threat class, a
confidence score, a severity level, and a list of human-readable SHAP
evidence strings — plus, when relevant, a kill-chain ID linking it to
other alerts from the same attacker.

**"Is it actively blocking anything?"**
No — deliberately passive/read-only. It observes and alerts; response
and blocking would be a separate system layered on top, by design
(reduces blast radius of the tool itself).

---

## 7. Cheat-sheet: the seven detection classes

| Class | What it looks like on the wire |
|---|---|
| `port_scan` | One source IP touching many destination ports very fast |
| `ddos` | A flood of packets/connections aimed at overwhelming a target |
| `c2_beaconing` | Regular, periodic "check-in" connections — classic malware command-and-control pattern |
| `dns_anomaly` | Unusual DNS query patterns (e.g. DNS tunneling, algorithmically-generated domains) |
| `exfiltration` | Large, sustained outbound data transfer — much more upload than download |
| `malware_tls` | TLS/encrypted traffic with fingerprints characteristic of known malware families |
| `benign` | Normal, unremarkable traffic — the baseline everything else is judged against |

---

## 8. One-line demo narration script (optional)

> "We're going to run a real port scan from this attacker machine against
> this victim machine, on an isolated network. Watch the dashboard — in
> a few seconds you'll see Zeek's telemetry get turned into features,
> streamed through Kafka, scored by our model, and show up here as a
> `port_scan` alert with a confidence score and the actual evidence the
> model used to decide that. Then we'll run a second, different kind of
> attack from the same source, and show you the Kill Chains page
> automatically linking the two together as one multi-stage attack."
