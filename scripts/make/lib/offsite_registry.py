"""A registry whose packument points every non-tarball URL at a second server.

Answers the question the origin policy rests on: which URLs in a packument does each
client actually fetch? `dist.tarball` is known to be fetched by all of them. The rest of
the document carries URLs too, and the policy only guards `dist.tarball` because pacote
discards the host of `dist.attestations.url`. That is pacote's behaviour, not protocol,
so it holds for npm and says nothing about pnpm, yarn or bun.

Two servers. The registry serves a working package, so the install succeeds and every
client gets far enough to fetch whatever else it would fetch. The recorder answers 404 to
everything and logs what was asked for: a request that reaches it is a URL the client
used as written, which is a URL the proxy would never see.

Both servers log what they were asked for, so a URL the client rewrote onto the registry
is visible as well as one it used as written.

Usage: offsite_registry.py <registry port> <recorder port> <recorder log> <registry log>
"""

import base64
import hashlib
import http.server
import io
import json
import socketserver
import sys
import tarfile
import threading


def make_tarball() -> bytes:
    """A minimal but real npm tarball, so installs actually complete."""
    manifest = json.dumps(
        {"name": "widget", "version": "1.0.0", "description": "measurement fixture"}
    ).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo("package/package.json")
        info.size = len(manifest)
        tar.addfile(info, io.BytesIO(manifest))
    return buf.getvalue()


def packument(tarball: bytes, registry: str, recorder: str) -> bytes:
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode()
    version = {
        "name": "widget",
        "version": "1.0.0",
        "description": "measurement fixture",
        "dist": {
            "tarball": f"{registry}/widget/-/widget-1.0.0.tgz",
            "integrity": integrity,
            # npm defines a packument's `shasum` as the tarball's SHA-1; integrity is the check.
            "shasum": hashlib.sha1(tarball).hexdigest(),  # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
            "attestations": {
                "url": f"{recorder}/attestations",
                "provenance": {"predicateType": "https://slsa.dev/provenance/v1"},
            },
            "signatures": [{"keyid": "SHA256:offsite", "sig": "not-a-real-signature"}],
        },
        "homepage": f"{recorder}/homepage",
        "repository": {"type": "git", "url": f"{recorder}/repository.git"},
        "bugs": {"url": f"{recorder}/bugs"},
    }
    return json.dumps(
        {
            "name": "widget",
            "dist-tags": {"latest": "1.0.0"},
            "versions": {"1.0.0": version},
            "homepage": f"{recorder}/homepage",
            "repository": {"type": "git", "url": f"{recorder}/repository.git"},
            "bugs": {"url": f"{recorder}/bugs"},
        }
    ).encode()


class Threaded(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def registry_handler(document: bytes, tarball: bytes, log_path: str):
    lock = threading.Lock()

    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def note(self):
            agent = self.headers.get("User-Agent", "-")
            with lock, open(log_path, "a") as out:
                out.write(f"{self.command} {self.path}\t{agent}\n")

        def _send(self, code, body, content_type):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self.note()
            path = self.path.split("?")[0]
            if path in ("/widget", "/widget/"):
                self._send(200, document, "application/vnd.npm.install-v1+json")
            elif path == "/widget/-/widget-1.0.0.tgz":
                self._send(200, tarball, "application/octet-stream")
            else:
                self._send(404, b'{"error":"Not found"}', "application/json")

    return H


def recorder_handler(log_path: str):
    lock = threading.Lock()

    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def record(self):
            agent = self.headers.get("User-Agent", "-")
            with lock, open(log_path, "a") as out:
                out.write(f"{self.command} {self.path}\t{agent}\n")
            body = b'{"error":"Not found"}'
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = record
        do_HEAD = record
        do_POST = record

    return H


def main() -> None:
    registry_port, recorder_port, recorder_log, registry_log = (
        int(sys.argv[1]),
        int(sys.argv[2]),
        sys.argv[3],
        sys.argv[4],
    )
    tarball = make_tarball()
    document = packument(
        tarball,
        f"http://127.0.0.1:{registry_port}",
        f"http://127.0.0.1:{recorder_port}",
    )

    recorder = Threaded(("127.0.0.1", recorder_port), recorder_handler(recorder_log))
    threading.Thread(target=recorder.serve_forever, daemon=True).start()
    Threaded(
        ("127.0.0.1", registry_port),
        registry_handler(document, tarball, registry_log),
    ).serve_forever()


if __name__ == "__main__":
    main()
