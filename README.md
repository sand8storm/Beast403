# Beast403

![python](https://img.shields.io/badge/python-3.10%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![status](https://img.shields.io/badge/status-v0.1-orange)

**An accuracy-first 403 bypass scanner.** Most 403 bypass tools judge success by
a single shallow signal (status code or response length) and drown you in false
positives. Beast403's whole point is the opposite: it verifies every candidate
against **live, per-target oracles** and reports only the bypasses that survive,
each with a confidence score and a plain-English reason.

> ⚠️ **Authorized testing only.** Use Beast403 exclusively against systems you
> are explicitly permitted to test (in-scope bug-bounty / pentest engagements).
> You are responsible for complying with the law and program rules.

---

## Why it's different

A bypass is a **parser differential**: the guard (proxy/WAF) and the backend
normalize the same request differently, so a path the guard reads as "not the
blocked one" is normalized by the backend back into the protected resource.
Tools that fire those tricks are common. The hard part is not getting fooled by:

- `200` responses whose body says *Forbidden* / *Login* (soft blocks)
- redirects to the home or login page
- SPA / catch-all sites where **every** path returns the same `200` shell
- custom `404` pages served with status `200`
- dynamic content (tokens, dates) that shifts response length

Beast403 kills these by building a reference set first and classifying every
response against it.

## How it works (pipeline)

```
URL → fingerprint → oracles → techniques → responses → features → verdicts
```

1. **Fingerprint** the stack (server / WAF) to pick which tricks are worth firing.
2. **Calibrate oracles** — measured live, per target:
   - *baseline*: the target path as-is (usually `403`)
   - *not-found*: a few random garbage paths (also detects SPA/catch-all)
   - *public*: a known-public path (home/root)
   - *authorized* (optional): with `--auth-header`, the shape of real success
3. **Generate techniques** — paths, headers, methods, encoding (~87 probes),
   gated by the fingerprint. A technique only *generates* candidates; it never
   judges success.
4. **Verify** each response with a five-rung ladder that compares its
   **structure** (a SimHash of the tag skeleton, not its size) to the oracles:
   matches the block page → reject; matches not-found / SPA → reject; matches the
   public page → reject; has denial markers → reject; otherwise score a
   transparent, additive confidence and report it.

## Installation

```bash
git clone https://github.com/sand8storm/Beast403.git
cd Beast403

# use a virtual environment (required on Kali/Debian due to PEP 668)
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# install as a package -> gives you the `beast403` command, runnable anywhere
pip install -e .
```

Requires Python 3.10+. After `pip install -e .` you can run either:

```bash
beast403 https://target.com /admin           # console command
python -m beast403.cli https://target.com /admin   # equivalent
```

## Usage

```bash
# basic scan
python -m beast403.cli https://target.com /admin

# markdown PoC to a file
python -m beast403.cli https://target.com /admin -o markdown --out-file poc.md

# JSON, only findings above 60% confidence
python -m beast403.cli https://target.com /admin -o json --min-confidence 0.6

# supply an authorized baseline (O4 oracle) for higher accuracy
python -m beast403.cli https://target.com /admin --auth-header "Cookie: session=..."

# see every raw 200 (pre-verifier) to understand the false-positive problem
python -m beast403.run https://target.com /admin
```

## Benchmark (the point of the project)

Prove the false-positive claim with numbers. Build a labeled file from your lab:

```json
{
  "base": "https://localhost:8443",
  "targets": [
    {"path": "/admin", "bypassable": true},
    {"path": "/nope",  "bypassable": false}
  ]
}
```

```bash
python -m beast403.bench ground_truth.json --min-confidence 0.5
# -> precision / recall / false-positive-rate
```

## Project layout

```
beast403/
├── cli.py            full pipeline + options (main entry)
├── run.py            raw pre-verifier dump (debugging / teaching)
├── bench.py          precision / recall / FP-rate vs ground truth
├── core/             models (data contracts) + async engine
├── recon/            stack/WAF fingerprinting
├── oracle/           oracle calibration + SPA detection
├── techniques/       paths · headers · methods · encoding · registry
├── analysis/         features · similarity (SimHash) · verifier
└── report/           json · markdown PoC
```

## Known limitations

- **Raw paths (solved):** clients like httpx normalize the URL (collapsing `..`,
  `//`, re-encoding) or reject mangled paths, silently defeating path tricks.
  Beast403 ships a raw socket sender (`--engine raw`, the **default**) that puts
  the exact request-target bytes on the wire, so `/admin/..;/`, `/%2fadmin`, and
  `/./admin/./` are sent as written. Use `--engine httpx` for the normalizing
  client if you ever need it.
- Thresholds (`SAME`, confidence weights) ship with sensible defaults; calibrate
  them on your own labeled data with `bench.py`.
- HTTP/2 and protocol-level differentials are out of scope for v1.
- The adaptive mutation engine (learning which payloads to try from feedback) is
  future work.

## Troubleshooting

**`ModuleNotFoundError: No module named 'beast403'`**
You're running from the wrong directory, or the package isn't installed. The
permanent fix is `pip install -e .` from the repo root (then `beast403` works
from anywhere). Without installing, you must run `python -m beast403.cli` from
the directory that *contains* the `beast403/` package folder.

**`error: externally-managed-environment` (Kali/Debian)**
PEP 668 blocks system-wide pip. Use a virtualenv (shown in Installation), or as
a last resort `pip install -e . --break-system-packages`.

**`beast403: command not found`**
The console command only exists after `pip install -e .` inside an active
virtualenv. Re-activate it with `source .venv/bin/activate`.

**The tool finds nothing / paths look normalized**
Make sure you're on the default `--engine raw`. The `httpx` engine normalizes
paths and can hide path-based bypasses.

## License

MIT — see [LICENSE](LICENSE).
