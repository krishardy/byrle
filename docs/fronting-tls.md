# Fronting byrle with TLS

byrle serves plain HTTP. A proxy reached by name goes behind nginx on TLS, below. `make
smoke-tls-front` runs it against the proxy with a local CA and checks that nginx passes
everything through. It ran on 2026-10-12 with nginx 1.28.3. The configuration here is the
one it runs, with the name and certificate paths changed.

Caddy is not a supported front. Decided 2026-10-12
([tls-front-nginx](engineering_decisions/tls-front-nginx.md)).

## The proxy

```
BYRLE_LISTEN=127.0.0.1:8080
BYRLE_PROXY_URL=https://byrle.example.com
```

`BYRLE_PROXY_URL` is the front's address. It is what the proxy writes into artifact
URLs, so it is what lockfiles record. `BYRLE_LISTEN` on loopback keeps the plain HTTP
port off the network.

The path of `BYRLE_PROXY_URL` is where the proxy answers, and a request outside it is
answered 404. With `https://byrle.example.com/registry/`, the front passes `/registry/...`
through unchanged: `location /registry/` with `proxy_pass http://127.0.0.1:8080;`, with no
path after the port. The configuration below uses the root, `/`.

The admin console, when `BYRLE_CONSOLE_URL` is set, answers under that URL's path. On the
proxy's listener the two paths may not contain each other, so the proxy at `/` and a
console beside it need `BYRLE_CONSOLE_LISTEN`
([console-listener](engineering_decisions/console-listener.md)).

## nginx

```
server {
    listen 443 ssl;
    server_name byrle.example.com;
    ssl_certificate /etc/letsencrypt/live/byrle.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/byrle.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Byrle-RP-Key <the value of BYRLE_RP_KEY>;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 300s;
    }
}
```

| Directive | Why |
|---|---|
| `proxy_buffering off` | streams an artifact through as the proxy verifies it, rather than nginx holding the whole response |
| `proxy_read_timeout 300s` | the proxy reads, filters and rewrites a metadata document before its first byte, and a large one takes longer than nginx's default 60 s. `next`'s 4.4 MB packument took 21 s in [latency-benchmarks](engineering_decisions/latency-benchmarks.md) |
| `proxy_set_header Host $http_host` | passes the name the client used. The proxy writes `BYRLE_PROXY_URL` into documents when it is set, and the `Host` otherwise |
| `proxy_http_version 1.1` | keeps upstream connections open between requests |
| `proxy_set_header X-Forwarded-For $remote_addr` | the client's address, replacing any the client sent. byrle reads the last entry |
| `proxy_set_header X-Byrle-RP-Key` | authenticates nginx to byrle. Only a request carrying `BYRLE_RP_KEY` has its `X-Forwarded-For` read; any other is taken to come from its peer. The registry is not sent either header |

The certificate paths are certbot's. The smoke test uses a local certificate.

`BYRLE_RP_KEY` is at least 32 bytes; `openssl rand -hex 32` makes one. The nginx
configuration then holds the key, so it is readable only by root and nginx. byrle keeps its
SHA-256 and compares digests. The console reads the client's address this way, for the
login rate limit and the account event log's `source`. Asked for by the user 2026-10-13.

## What the smoke test checks

Through nginx, on TLS:

| Check | Result |
|---|---|
| `/-/byrle/health` | 200 |
| an artifact nothing has analysed | 503 with `Retry-After: 1` and `x-byrle-not-ready: artifact-analysis` |
| `npm install debug@4.4.1` | installs; the lockfile records nginx's `https://` address |
| `pip install six==1.17.0` | installs |

With `proxy_hide_header x-byrle-not-ready` added to the nginx configuration, the test
failed: `x-byrle-not-ready did not pass through`.

## Clients and a private CA

A certificate from a public CA needs nothing on the clients. One from a private CA does:

| Client | Trusts a CA from |
|---|---|
| npm, pnpm, yarn, bun | `NODE_EXTRA_CA_CERTS=/path/ca.pem`; npm also `npm config set cafile` |
| pip | `pip config set global.cert /path/ca.pem` |
| uv | `SSL_CERT_FILE=/path/ca.pem` |

npm and pip were run this way against the local CA. The other lines are those clients'
documented settings, not run here.
