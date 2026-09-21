"""Measure npm tarball sizes, to size the buffer the analysis path needs."""
import json, subprocess, concurrent.futures as cf

PACKAGES = """
lodash express react react-dom next typescript webpack eslint chalk debug ms axios
@babel/core @babel/traverse @babel/preset-env rollup vite esbuild prettier jest mocha
commander yargs inquirer rxjs moment date-fns dayjs uuid semver glob rimraf fs-extra
tslib zod yup joi socket.io ws redis mongoose pg mysql2 sequelize prisma knex
@types/node @types/react vue svelte angular @angular/core @angular/common rxjs-compat
electron puppeteer playwright cypress selenium-webdriver sharp canvas node-sass sass
tailwindcss postcss autoprefixer bootstrap jquery three d3 chart.js echarts
aws-sdk @aws-sdk/client-s3 firebase googleapis stripe twilio nodemailer
graphql apollo-server @apollo/client bull ioredis winston pino bunyan
bufferutil node-gyp-build node-gyp typescript-eslint @grpc/grpc-js protobufjs
""".split()


def size(name):
    """The tarball's length, from a one-byte range request's Content-Range."""
    try:
        doc = json.loads(subprocess.run(
            ["curl", "-sSL", "--max-time", "60", "-H",
             "Accept: application/vnd.npm.install-v1+json",
             f"https://registry.npmjs.org/{name}"],
            capture_output=True, text=True, timeout=120).stdout)
        latest = doc["dist-tags"]["latest"]
        url = doc["versions"][latest]["dist"]["tarball"]
        head = subprocess.run(
            ["curl", "-sSL", "-D", "-", "-o", "/dev/null", "-r", "0-0",
             "--max-time", "60", url],
            capture_output=True, text=True, timeout=120).stdout
        for line in head.splitlines():
            if line.lower().startswith("content-range:"):
                return (name, latest, int(line.split("/")[-1].strip()))
        return (name, latest, None)
    except Exception as e:
        print(f"  {name}: {type(e).__name__} {e}")
        return (name, None, None)


with cf.ThreadPoolExecutor(max_workers=16) as pool:
    rows = [r for r in pool.map(size, PACKAGES) if r[2]]

rows.sort(key=lambda r: r[2])
n = len(rows)
print(f"{n} packages measured, latest version of each")
for label, i in [("min", 0), ("p50", n // 2), ("p90", int(n * 0.9)),
                 ("p99", int(n * 0.99)), ("max", n - 1)]:
    name, ver, b = rows[i]
    print(f"  {label:>4}  {b:>12,} bytes  {name}@{ver}")
for ceiling in (8, 16, 32, 64, 128, 256):
    over = [r for r in rows if r[2] > ceiling * 1024 * 1024]
    print(f"  over {ceiling:>3} MiB: {len(over):>2}  {[r[0] for r in over][:6]}")
