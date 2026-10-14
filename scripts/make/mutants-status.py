#!/usr/bin/env python3
"""How far the `make mutants` run is: mutants done of those found, each outcome counted,
the time so far with an estimate of what is left, and each mutant missed or timed out.

cargo-mutants rewrites target/mutants.out/outcomes.json as each mutant finishes.
"""

import datetime
import json
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parents[2] / "target" / "mutants.out"


def when(stamp):
    return datetime.datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def main():
    try:
        outcomes = json.loads((OUT / "outcomes.json").read_text())
        found = len(json.loads((OUT / "mutants.json").read_text()))
    except FileNotFoundError:
        sys.exit(f"no mutants run in {OUT}")
    done = sum(1 for o in outcomes["outcomes"] if o["scenario"] != "Baseline")
    counts = ", ".join(
        f"{outcomes[k]} {k}" for k in ("caught", "missed", "timeout", "unviable"))
    started = when(outcomes["start_time"])
    finished = outcomes.get("end_time")
    if finished:
        took = (when(finished) - started).total_seconds()
        print(f"finished: {done} of {found} in {took / 60:.0f} min: {counts}")
    else:
        so_far = (datetime.datetime.now(datetime.timezone.utc) - started).total_seconds()
        left = so_far / done * (found - done) if done else None
        estimate = f", about {left / 60:.0f} min left" if left is not None else ""
        print(f"running: {done} of {found} after {so_far / 60:.0f} min{estimate}: {counts}")
    for name in ("missed", "timeout"):
        listed = (OUT / f"{name}.txt").read_text().splitlines() if (OUT / f"{name}.txt").exists() else []
        for line in listed:
            print(f"{name.upper()}  {line}")


if __name__ == "__main__":
    main()
