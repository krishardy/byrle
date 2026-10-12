# Fronting byrle with TLS

byrle serves plain HTTP. A proxy reached by name goes behind a TLS front: Caddy or nginx,
below. `make smoke-tls-front` runs both against the proxy with a local CA and checks that
the front passes everything through. It ran on 2026-09-29 with Caddy 2.10.2 and nginx
1.28.0, built from source; the configurations here are the ones it runs, with the name and
certificate paths changed.

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
through unchanged: Caddy's `handle /registry/*`, not `handle_path`, which strips it; nginx's
`location /registry/` with `proxy_pass http://127.0.0.1:8080;`, with no path after the
port. The configurations below use the root, `/`, which needs neither.

The admin console, when `BYRLE_CONSOLE_URL` is set, answers under that URL's path. On the
proxy's listener the two paths may not contain each other, so the proxy at `/` and a
console beside it need `BYRLE_CONSOLE_LISTEN`
([console-listener](engineering_decisions/console-listener.md)).

## Caddy

```
byrle.example.com {
	reverse_proxy 127.0.0.1:8080 {
		flush_interval -1
	}
}
```

- Caddy obtains and renews the certificate for `byrle.example.com` from Let's Encrypt
  on its own, given a public DNS name and ports 80 and 443 reachable. That is Caddy's
  documented default. The smoke test uses a local certificate with `tls <cert> <key>`
  instead, so the ACME path is not what it ran.
- `flush_interval -1` writes each chunk to the client as it arrives, so an artifact streams
  through rather than being held.
- Caddy passes the client's `Host` and every response header through as they are.

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

The certificate paths are certbot's. The smoke test uses a local certificate.

## What the smoke test checks

For each front, through TLS:

| Check | Caddy | nginx |
|---|---|---|
| `/-/byrle/health` | 200 | 200 |
| an artifact nothing has analysed | 503 with `Retry-After: 1` and `x-byrle-not-ready: artifact-analysis` | the same |
| `npm install debug@4.4.1` | installs; the lockfile records the front's `https://` address | the same |
| `pip install six==1.17.0` | installs | installs |

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
