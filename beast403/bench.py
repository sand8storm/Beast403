"""Benchmark Beast403 against labeled ground truth -> precision / recall / FP-rate.

This is the number that proves the whole thesis ("lowest false-positive rate").
Build the ground-truth file from your lab, where you KNOW the answer.

ground_truth.json:
{
  "base": "https://localhost:8443",
  "targets": [
    {"path": "/admin",  "bypassable": true},
    {"path": "/secret", "bypassable": true},
    {"path": "/nope",   "bypassable": false}
  ]
}

    python -m beast403.bench ground_truth.json --min-confidence 0.5

A target counts as 'predicted bypassable' if any finding is a BYPASS at or above
--min-confidence. We then compare predictions to labels.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from types import SimpleNamespace

from .cli import run
from .core.models import Verdict


async def _bench(gt_path: str, min_conf: float):
    gt = json.loads(open(gt_path, encoding="utf-8").read())
    base = gt["base"]
    tp = fp = tn = fn = 0
    rows = []
    for t in gt["targets"]:
        args = SimpleNamespace(
            url=base, path=t["path"], concurrency=15, delay_ms=0, timeout=8.0,
            public_path="/", auth_header=None, output="console", all=False,
            min_confidence=min_conf, engine="raw",
        )
        findings = await run(args)
        predicted = any(f.verdict == Verdict.BYPASS and f.confidence >= min_conf
                        for f in findings)
        actual = bool(t["bypassable"])
        if predicted and actual:
            tp += 1; result = "TP"
        elif predicted and not actual:
            fp += 1; result = "FP"
        elif not predicted and actual:
            fn += 1; result = "FN"
        else:
            tn += 1; result = "TN"
        rows.append((t["path"], actual, predicted, result))
    return tp, fp, tn, fn, rows


def main(argv=None) -> None:
    p = argparse.ArgumentParser(prog="beast403-bench")
    p.add_argument("ground_truth", help="path to ground_truth.json")
    p.add_argument("--min-confidence", type=float, default=0.5)
    a = p.parse_args(argv)

    tp, fp, tn, fn, rows = asyncio.run(_bench(a.ground_truth, a.min_confidence))

    print(f"\n{'path':30} {'actual':8} {'pred':6} result")
    print("-" * 56)
    for path, actual, pred, result in rows:
        print(f"{path:30} {str(actual):8} {str(pred):6} {result}")

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    print(f"\nTP={tp}  FP={fp}  TN={tn}  FN={fn}")
    print(f"precision={precision:.0%}   recall={recall:.0%}   false-positive-rate={fpr:.0%}")


if __name__ == "__main__":
    main()
