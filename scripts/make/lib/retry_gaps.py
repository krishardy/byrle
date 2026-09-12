"""How many times one request was reissued, and how long the client waited between.

Reads `<timestamp> <path>` pairs on stdin, one per deferred request, and prints
`<attempts> <comma-separated gaps in seconds>`.

Counted per path, not per request. npm asks for `/npm` as well as the package on every
round, so a raw count reports twice the retries it made. The number that matters is how
many times a single request was reissued, and the gaps between those attempts are what
`Retry-After` has to land inside.
"""

import sys
from collections import defaultdict
from datetime import datetime


def main() -> None:
    by_path = defaultdict(list)
    for line in sys.stdin:
        parts = line.split()
        if len(parts) != 2:
            continue
        try:
            by_path[parts[1]].append(datetime.fromisoformat(parts[0].rstrip("Z")))
        except ValueError:
            continue

    if not by_path:
        print("0 -")
        return

    # The busiest path is the one the client kept reissuing.
    stamps = sorted(max(by_path.values(), key=len))
    gaps = [f"{(b - a).total_seconds():.1f}" for a, b in zip(stamps, stamps[1:])]
    print(f"{len(stamps)} {','.join(gaps) if gaps else '-'}")


if __name__ == "__main__":
    main()
