\# Beast403 — Development Context



Beast403 is an accuracy-first 403/401 bypass scanner. Its differentiator is a

\*\*verification-first\*\* design that kills false positives other tools produce.

Every change must sharpen that edge — depth in 403 bypass, never breadth.



\## Core philosophy — NEVER violate

\- \*\*Verification-first:\*\* a Technique NEVER decides whether a bypass succeeded.

&#x20; It only generates candidate requests (Probes). ALL judgment lives in

&#x20; `analysis/verifier.py`, against the `OracleSet`. Keep signal generation

&#x20; decoupled from judgment. This separation is the whole reason the tool works.

\- \*\*raw\_path is sacred:\*\* we NEVER normalize `raw\_path`. Path bypasses depend on

&#x20; exact bytes reaching the wire (`/admin/..;/`, `//admin`, `%2f`).

\- \*\*Explainability:\*\* every Finding carries a confidence score and plain reasons.

&#x20; Never replace the interpretable verdict ladder with an opaque model.



\## Strategic direction — depth, not breadth

\- Goal: make Beast403 the single best tool in the world for 403/401 bypass —

&#x20; lowest false-positive rate in the industry, rare-technique coverage, and

&#x20; scientific provability.

\- Do NOT turn this into a general framework or add unrelated tools (port scan,

&#x20; XSS, etc). Every feature must answer: "does this make Beast403 unbeatable at

&#x20; 403 specifically?" If no, reject it.



\## Architecture

Pipeline: URL → TargetProfile → OracleSet → \[Probe] → \[Response] → \[Features] → \[Finding]

\- `techniques/` — Probe generators. Add one by implementing the Technique

&#x20; Protocol (`base.py`) and registering in `registry.py`. `applies\_to()` is the

&#x20; fingerprint gate.

\- `analysis/verifier.py` — the judge. SimHash structural comparison + oracle

&#x20; distances + denial markers → Verdict + confidence.

\- `oracle/calibrator.py` — builds live per-target reference pages.



\## Benchmark ground truth (from independent lab: zack0x01/403-Bypass-lab)

Current measured state — Precision 100%, Recall \~67% (4/6 measurable):

\- Confirmed working: method, header(IP), path/encoding, case.

\- KNOWN GAPS (evidence-driven, prioritized):

&#x20; 1. Coverage gap: no query-string / parameter techniques (missed param

&#x20;    pollution). raw\_path currently conflates path + query — this is the root

&#x20;    cause and also breaks encoding techniques on URLs with `?`.

&#x20; 2. Payload-depth gap: method-override header only tries value "GET", not the

&#x20;    full method set.

&#x20; 3. Calibration blind spot: non-4xx baseline (200) is not surfaced to the user.

&#x20; 4. Finding inflation: structurally-identical bypasses shown many times; need

&#x20;    deduplication by (struct\_hash + length + oracle distances).



\## Working rules

\- We work on branch `dev-improvements`, never commit to `main` directly.

\- First build a benchmark harness (automate the lab measurement) BEFORE other

&#x20; changes, so every later improvement is measured before/after — not guessed.

\- Read the existing technique/module before adding or changing one.

\- Preserve the Technique Protocol and the dataclass pipeline. Don't restructure

&#x20; without reason.

