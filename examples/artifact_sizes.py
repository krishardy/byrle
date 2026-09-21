"""How large the artifacts a proxy actually serves are, per ecosystem.

The fetch path buffers a novel artifact to analyse it, so the bound on that buffer is set
by the sizes the proxy sees. The population that matters is the packages that appear in
dependency closures, not the packages that exist: a real install is mostly small
transitive utilities and a few large ones.

npm:  walk dependency edges from a seed of root packages, then ask each tarball's host for
      its length with a one-byte range request.
pypi: walk `requires_dist` from a seed, and read each file's `size` from the JSON API,
      which reports it without a fetch.

Usage: artifact_sizes.py npm|pypi <wanted> [out.json]
"""
import json
import re
import subprocess
import sys
import concurrent.futures as cf
import threading

NPM_SEED = """
next react react-dom vue svelte @angular/core express koa fastify nestjs mongoose pg
redis ioredis prisma knex sequelize eslint typescript webpack vite rollup esbuild
prettier jest mocha vitest cypress playwright puppeteer commander yargs inquirer chalk
ora d3 chart.js echarts three tailwindcss postcss sass @aws-sdk/client-s3 firebase
googleapis stripe twilio nodemailer graphql @apollo/client socket.io axios got
node-fetch winston pino lodash moment date-fns rxjs zod yup sharp electron
""".split()

PYPI_SEED = """
requests urllib3 boto3 botocore numpy pandas scipy scikit-learn matplotlib django flask
fastapi sqlalchemy alembic pydantic celery redis psycopg2-binary pymongo pytest tox black
ruff mypy poetry pip setuptools wheel click typer rich httpx aiohttp beautifulsoup4 lxml
pillow opencv-python torch tensorflow transformers langchain openai anthropic jupyter
notebook ipython dask pyarrow polars duckdb streamlit gradio uvicorn gunicorn
""".split()

NAME = re.compile(r"^[A-Za-z0-9._-]+")


def run(args, timeout=120):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout).stdout


def npm_packument(name):
    return json.loads(run([
        "curl", "-sSL", "--max-time", "60", "--retry", "2",
        "-H", "Accept: application/vnd.npm.install-v1+json",
        f"https://registry.npmjs.org/{name}"]))


def npm_entry(name):
    """The latest version's tarball url, its size, and the names it depends on."""
    doc = npm_packument(name)
    latest = doc["dist-tags"]["latest"]
    version = doc["versions"][latest]
    head = run(["curl", "-sSL", "-D", "-", "-o", "/dev/null", "-r", "0-0",
                "--max-time", "60", version["dist"]["tarball"]])
    size = None
    for line in head.splitlines():
        if line.lower().startswith("content-range:"):
            size = int(line.split("/")[-1].strip())
    return {
        "name": name, "version": latest, "size": size,
        "url": version["dist"]["tarball"],
    }, list(version.get("dependencies", {}))


def pypi_entry(name):
    """Every file of the latest version, with the size the API reports, and its deps."""
    doc = json.loads(run([
        "curl", "-sSL", "--max-time", "60", "--retry", "2",
        f"https://pypi.org/pypi/{name}/json"]))
    info = doc["info"]
    files = [{
        "name": name, "version": info["version"], "size": f["size"],
        "kind": f["packagetype"], "url": f["url"],
    } for f in doc["urls"] if f.get("size")]
    deps = []
    for spec in info.get("requires_dist") or []:
        # `name (>=1.0) ; extra == "dev"` — the runtime requirement is the part before `;`.
        if ";" in spec:
            continue
        found = NAME.match(spec.strip())
        if found:
            deps.append(found.group(0))
    return files, deps


def walk(ecosystem, wanted):
    """Breadth-first over dependency edges until `wanted` packages have been measured."""
    entry = npm_entry if ecosystem == "npm" else pypi_entry
    seed = NPM_SEED if ecosystem == "npm" else PYPI_SEED
    seen, rows, queue = set(seed), [], list(seed)
    lock = threading.Lock()
    with cf.ThreadPoolExecutor(max_workers=24) as pool:
        while queue and len(rows) < wanted:
            batch, queue = queue[:240], queue[240:]

            def one(name):
                try:
                    return entry(name)
                except Exception:
                    return None

            for got in pool.map(one, batch):
                if not got:
                    continue
                found, deps = got
                with lock:
                    rows.extend(found if isinstance(found, list) else [found])
                    for dep in deps:
                        if dep not in seen:
                            seen.add(dep)
                            queue.append(dep)
            print(f"  {len(rows)} measured, {len(queue)} queued", file=sys.stderr)
    return [r for r in rows if r.get("size")]


def report(ecosystem, rows):
    rows.sort(key=lambda r: r["size"])
    n = len(rows)
    print(f"\n{ecosystem}: {n} artifacts")
    for label, q in [("min", 0.0), ("p50", 0.5), ("p75", 0.75), ("p90", 0.9),
                     ("p95", 0.95), ("p99", 0.99), ("p99.9", 0.999), ("max", 1.0)]:
        r = rows[min(int(n * q), n - 1)]
        print(f"  {label:>6}  {r['size']:>12,}  {r['name']}@{r['version']}")
    total = sum(r["size"] for r in rows)
    print(f"  mean   {total // n:>12,}")
    for mib in (1, 4, 8, 16, 32, 64, 128, 256, 512):
        over = [r for r in rows if r["size"] > mib * 1024 * 1024]
        if not over:
            print(f"  over {mib:>4} MiB: {0:>5}  (0.00%)")
            break
        names = ", ".join(f"{r['name']}" for r in over[-3:])
        print(f"  over {mib:>4} MiB: {len(over):>5}  ({len(over) / n:.2%})  largest: {names}")


if __name__ == "__main__":
    ecosystem, wanted = sys.argv[1], int(sys.argv[2])
    rows = walk(ecosystem, wanted)
    report(ecosystem, rows)
    if len(sys.argv) > 3:
        json.dump(rows, open(sys.argv[3], "w"))
