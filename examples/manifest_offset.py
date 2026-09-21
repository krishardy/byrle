"""How much of an npm tarball the install-script reader has to see.

`analysis::member` walks the tar sequentially and returns at the first `package.json`,
so it needs a prefix of the gzip stream, not the whole artifact. This measures the
smallest prefix each package's manifest is readable from, which is the bound the fetch
path needs rather than the artifact's size.
"""
import json
import subprocess
import zlib
import concurrent.futures as cf

PACKAGES = """
lodash express react react-dom next typescript webpack eslint chalk debug ms axios
@babel/core @babel/traverse rollup vite esbuild prettier jest mocha commander yargs
rxjs moment date-fns dayjs uuid semver glob fs-extra tslib zod socket.io ws redis
mongoose pg mysql2 sequelize prisma knex @types/node @types/react vue svelte
@angular/core electron puppeteer playwright cypress selenium-webdriver sharp
tailwindcss postcss bootstrap jquery three d3 chart.js echarts aws-sdk
@aws-sdk/client-s3 firebase googleapis stripe twilio nodemailer graphql
@apollo/client bull ioredis winston pino bufferutil node-gyp-build node-gyp
protobufjs @grpc/grpc-js
""".split()

# The prefixes to try, smallest first. The answer is the first one the manifest is
# readable from.
PREFIXES = [16 * 1024, 64 * 1024, 256 * 1024, 1024 * 1024, 4 * 1024 * 1024]
BLOCK = 512


def manifest_in(prefix: bytes) -> bool:
    """Whether a complete `package.json` member is readable from these bytes alone."""
    try:
        raw = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(prefix)
    except zlib.error:
        return False
    at = 0
    while at + BLOCK <= len(raw):
        header = raw[at : at + BLOCK]
        name = header[:100].split(b"\0", 1)[0].decode("utf-8", "replace")
        if not name:
            return False
        size_field = header[124:136].split(b"\0", 1)[0].strip()
        try:
            size = int(size_field, 8) if size_field else 0
        except ValueError:
            return False
        body = at + BLOCK
        if name.endswith("package.json"):
            # Readable only if every byte of the member is in the prefix.
            return body + size <= len(raw)
        at = body + (size + BLOCK - 1) // BLOCK * BLOCK
    return False


def fetch(url: str, last: int) -> bytes:
    return subprocess.run(
        ["curl", "-sSL", "--max-time", "90", "-r", f"0-{last}", url],
        capture_output=True, timeout=180).stdout


def measure(name: str):
    try:
        doc = json.loads(subprocess.run(
            ["curl", "-sSL", "--max-time", "60", "-H",
             "Accept: application/vnd.npm.install-v1+json",
             f"https://registry.npmjs.org/{name}"],
            capture_output=True, text=True, timeout=120).stdout)
        latest = doc["dist-tags"]["latest"]
        url = doc["versions"][latest]["dist"]["tarball"]
        for prefix in PREFIXES:
            if manifest_in(fetch(url, prefix - 1)):
                return (name, latest, prefix)
        return (name, latest, None)
    except Exception as e:
        print(f"  {name}: {type(e).__name__} {e}")
        return (name, None, None)


with cf.ThreadPoolExecutor(max_workers=12) as pool:
    rows = list(pool.map(measure, PACKAGES))

answered = [r for r in rows if r[2]]
unanswered = [r for r in rows if r[1] and not r[2]]
print(f"{len(answered) + len(unanswered)} packages, latest version of each")
for prefix in PREFIXES:
    at = [r for r in answered if r[2] == prefix]
    within = len([r for r in answered if r[2] <= prefix])
    print(f"  readable from {prefix // 1024:>5} KiB: {len(at):>3} here, {within:>3} at or below")
if unanswered:
    print(f"  not readable from {PREFIXES[-1] // 1024} KiB: {[r[0] for r in unanswered]}")
