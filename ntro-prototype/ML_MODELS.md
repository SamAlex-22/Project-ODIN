# ML Models

All three of the prototype's detectors are now driven by trained classifiers
instead of hand-picked thresholds. All three were trained and validated in a
separate exploration repo (`recon-ml-poc/`, not part of this project) before
being wired in here — see that repo's `README.md` for the full methodology,
every dead end, and every honest caveat. This page is the short version:
what's running in production, on what data, checked how.

## What's running

| Detector | Model | File | Replaces |
|---|---|---|---|
| `backend/detectors/ddos.py` | RandomForestClassifier | `backend/ml_models/ddos_model.joblib` | fixed `packet_rate > 200` threshold |
| `backend/detectors/recon.py` | RandomForestClassifier | `backend/ml_models/recon_model_v3.joblib` | fixed `unique_ports > 15 OR unique_hosts > 10` threshold |
| `backend/detectors/c2.py` | RandomForestClassifier, range-gated | `backend/ml_models/c2_model.joblib` | fixed `cv <= 0.35` threshold, **within a validated range only** — see below |

All three loaded models fall back to their original fixed-threshold rule if the
`.joblib` file is missing or fails to load (e.g. scikit-learn absent from the
venv) — a live demo failing outright is worse than briefly running the older,
still-functional rule. `c2.py` also falls back to the rule *by design* outside
two specific input ranges its training data never covered — this isn't a
missing-file fallback, it's a deliberate, verified safety gate (see below).

## Features (must match training exactly)

**DDoS** (`backend/detectors/features.py` + `ddos.py`), over the same 10s
rolling window the original rule used:
- `packet_rate` — connections in the window (the rule's only signal)
- `unique_dst_ports`, `dst_port_entropy`
- `mean_inter_arrival`, `std_inter_arrival`

**Recon** (`features.py` + `recon.py`), over the same 60s per-source window:
- `unique_ports`, `unique_hosts`, `connection_count` (the rule's signals)
- `port_entropy`, `port_range_span`
- `mean_inter_arrival`, `std_inter_arrival`

Source-IP entropy / unique source-IP count (the DDoS rule's old *supporting*
evidence) are deliberately **not** model inputs — every packet in the
training capture came from the same loopback address, so that signal was a
zero-variance constant during training. They're still shown in the alert's
evidence list as human-readable context, just never fed to the model.

**C2** (`c2.py`), per `(src, dst, dst_port)` key, capped at the same 20
most-recent observations the detector already keeps:
- `observation_count`, `mean_interval`, `std_interval`, `cv` (the rule's
  own statistic)

## Validation (done in `recon-ml-poc/`, not here)

All three models were validated with **GroupKFold cross-validation grouped
by capture session** (never a random row split — adjacent feature rows from
dense time-snapshotting are heavily correlated, so a random split would leak
near-duplicate rows across train/test and produce a meaningless accuracy
number), and scored by **pooled confusion matrix** across all folds.

| Model | Rows | Sessions | Rule F1 | Model F1 |
|---|---|---|---|---|
| DDoS (RandomForest) | 10,133 | 80 | 0.921 | 0.994 |
| Recon (RandomForest) | 9,990 | 99 | 0.984 | 1.000 |
| C2 (RandomForest, gated) | 7,265 | 50 | 0.739 | 0.966 |

DDoS and recon are clean, low-cost improvements: the DDoS rule missed 566 of
3,870 flood windows in validation (mostly "low and slow" floods below its
fixed rate threshold); the model missed 45, and relies more on port entropy
and connection timing than on raw rate — the rule's only signal. Neither
model produced a meaningful false-positive cost.

**C2 is a real win with a real trade-off, not a free upgrade**: the rule
misses 2,399 of 5,792 c2 rows (it's an all-or-nothing gate that can't fire
before 5 observations exist), and the model recovers almost all of that —
but at a genuine cost of 132–269 false positives on benign rows across
folds, something the rule's strict gate can never produce by construction.
Choose Random Forest for max recall or Logistic Regression (98.7% precision,
94.3% recall) if false alarms matter more — see `recon-ml-poc/README.md`
for the full per-model numbers.

Full per-fold numbers, confusion matrices, and feature importances for all
three are in `recon-ml-poc/README.md`.

## C2's range gate — two real bugs found and fixed after training

Training and cross-validating the C2 model looked clean (table above). Wiring
it into the live detector and re-testing against realistic and actual demo
traffic surfaced two things the offline validation couldn't have caught,
because the validation could only ever score the model on the region its
own training data happened to cover:

1. **`observation_count` blind spot.** The training data's benign sessions
   (short, sparse by design) never accumulated more than 11 real connection
   events, while c2 sessions routinely reached the full 20-observation cap —
   checking `dataset_c2.csv` directly, *every* row with `observation_count >=
   12` is a c2 example, zero exceptions. A RandomForest given a region with
   no counterexamples just predicts the only class it's ever seen there.
   Verified empirically: 15 observations of clearly irregular (CV~0.6–0.7,
   well above the rule's 0.35 cutoff) synthetic benign traffic false-positived
   28/30 times (93%) on the unrestricted model — nowhere near the ~18% FP
   rate cross-validation reported, because CV could only score count<=11.
2. **`mean_interval` blind spot.** Every c2 training session used a 3-6s base
   beacon interval (kept short so the capture finished in a reasonable
   time) — no c2-labeled row has `mean_interval` above 6.01s. This project's
   own bundled demo asset, `traffic_pcaps/attack_c2.pcap`, beacons every
   ~30s. Replaying it still detected the beacon, but only at ~61% confidence
   (vs. 90%+ for in-range beacons) and later than the earliest possible
   observation — the model extrapolating into a region it was never shown a
   positive example for.

**Fix**: `c2.py` only consults the model while `observation_count <= 11`
**and** `mean_interval <= 7.0` (both constants named and explained in the
module's own docstring). Outside that range it falls back to the original
CV rule, which has neither blind spot because it doesn't depend on having
seen every input value during training. Re-verified after the fix: the demo
pcap now fires immediately and confidently (91%, via the rule) instead of
late and shaky (61%, via the model); the false-positive stress test dropped
from 93% back to 10%, in line with the validated rate; genuine in-range
beacons (3-6s interval) still correctly fire via the model at 90%+
confidence. **Takeaway for anyone extending this**: a clean cross-validation
number only certifies the region of input space your training data actually
covered — check what that region is (and what your actual demo assets look
like relative to it) before trusting a deployed model past it.

## Honest limitations (carried over from validation, not fixed by deploying)

- **Single test host**: all three training captures ran entirely against
  `127.0.0.1` — `unique_hosts` contributed ~0 importance to the recon model
  for exactly this reason. Real multi-host attack traffic is untested.
- **One generator per class**: `nmap -sT` for recon, Python `connect()`
  bursts for DDoS floods (not raw SYN packets — see `traffic_pcaps/` and
  `/api/replay` below for why), a scripted fixed-interval+jitter beacon for
  C2. A different tool's timing signature is unvalidated for any of the
  three.
- **"~10,000 rows" is not ~10,000 independent samples.** Row count comes
  from dense time-snapshotting within each session; the real diversity is
  the session count (80 / 99 / 50). See `recon-ml-poc/README.md`'s honesty
  notes before quoting a row count as if it were sample size.
- **C2's validated range is narrower than the rule's own design range.**
  The rule was always designed to handle beacons anywhere from 3s to 600s
  apart; the model is only trusted from 3-7s. That's not a bug to fix by
  raising the cap — it's a direct consequence of how short the training
  captures were kept, and would need longer/more varied captures to close.

## Replay for demo (`/api/replay/<threat>`)

`traffic_pcaps/*.pcap` are pre-recorded per-threat traffic samples. Pressing
"Replay <Threat> Traffic" (Threat Analysis page) has Zeek re-read that pcap
**offline** (`zeek -r`, inside the already-running `zeek_monitor` container,
in its own scratch directory) and appends the resulting `conn.log` lines
into the *live* log the real pipeline already tails — so a replayed event
flows through the exact same Kafka → detector → alert path as real traffic,
with the model scoring it for real.

This deliberately does not use `tcpreplay`: that needs raw-socket privileges
and passwordless `sudo` to run unattended from the backend, which can't be
relied on to work in front of a jury. Reading the same pcap offline with
Zeek produces byte-identical `conn.log` output with no such dependency.
Replayed events' timestamps are shifted so the earliest lands at "now"
(preserving the pcap's original relative spacing) before injection —
otherwise a years-old baked-in timestamp would break every detector's
rolling-window cutoff math.
