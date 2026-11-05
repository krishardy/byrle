# A client for each upstream service, sending only the headers it declares

- **Number:** 0133
- **Status:** Implemented 2026-11-05, for findings 25 and 39 of the security review:
  `src/service.rs`, each service's `Declared`, `scripts/make/clients.py`, and
  `Deciding::dated`'s `unservable`.
- **Related:** [upstream-ca-bundle](0081-upstream-ca-bundle.md),
  [virustotal](0104-virustotal.md)

## Context

Every request went through one of two `reqwest::Client`s: the upstream client, shared by
the proxy, the registry clients, the analyser, VirusTotal and the console's OIDC provider,
and `http::token_client`, which set `X-Byrle-Token` as a default header for the remote
commands and `byrle warm`. Neither set a redirect policy, so each followed up to 10
redirects to any host and from https to http.

reqwest 0.13.5 removes `Authorization`, `Cookie`, `Proxy-Authorization` and
`WWW-Authenticate` on a redirect to another host (`redirect.rs:239`), and keeps every other
header. `X-Byrle-Token` and VirusTotal's `x-apikey` followed a 3xx to wherever it pointed.
A client's default headers are merged in `execute_request` (`client.rs:2633`), after the
request is built, so a check on the built request does not see them.

## Decision

Each upstream service has a `service::Declared`: a name and every header it sets on a
request. `service::Service::new(declared, &connection)` is its client. Its requests are
built with `Service::get`, `head`, `post` or `request`, and `Asking::send` refuses, with a
panic naming the service and the header, any header on the built request that is not
declared. Every header name is fixed in code; only the values of the proxy's forwarded
headers come from the installing client, so an undeclared header is a bug a test reaches.
Headers reqwest and hyper add while sending (`Host`, the client's `User-Agent`, a body's
`Content-Length`) are not on the built request and are not declared.

| Service | Declared | Where |
|---|---|---|
| the upstream registries, forwarding | `accept`, `accept-encoding`, `if-none-match`, `if-modified-since` | `proxy::UPSTREAM` |
| the npm registry, the PyPI index | `accept`, `accept-encoding` | `npm::transport`, `pypi::transport` |
| the cargo index | `accept-encoding` | `cargo::transport` |
| crates.io's API | `user-agent` | `cargo::trustpub` |
| the Go module proxy, index and checksum database; the Maven repository; the key servers | none | `go::transport`, `go::heads`, `go::sumdb`, `maven::transport`, `maven::keys` |
| artifact hosts, attestation hosts, source archives | none | `analysis::run` |
| intel bundle hosts | none | `intel::fetch::BUNDLES` |
| GitHub's GraphQL API | `authorization`, `content-type` | `intel::fetch::GITHUB` |
| VirusTotal | `x-apikey`, `content-type`, `content-length` | `analysis::virustotal` |
| the OIDC provider | `authorization`, `content-type` | `console::oidc` |
| the deployment's API, the proxy's artifacts for `warm` | `content-type`; none | `remote`, `warm` |
| doctor's checks | `accept` | `doctor::probe` |

A `service::Connection` is how every service connects: the read timeout, the CA bundle
from `BYRLE_CA_BUNDLE`, and a credential sent on every request. The remote commands and
`byrle warm` use `http::token_connection`, which carries `X-Byrle-Token`; each service made
from it adds the header to each request, where the check sees it, and allows it besides its
own.

### Redirects

`service::may_follow` decides each redirect:

| Rule | Every service | A service with a credential |
|---|---|---|
| at most 10 redirects | yes | yes |
| never from https to another scheme | yes | yes |
| only to the first URL's scheme, host and port | no | yes |

A service has a credential when it declares `authorization`, `proxy-authorization`,
`cookie`, `x-apikey` or `x-byrle-token`, or its connection carries one. A redirect it does
not follow is answered as the 3xx. `https_only` is not set: an `http` upstream on loopback,
which the environment allows, would be refused. Registries keep following a redirect to
another host: the Gradle portal's files redirect to Central.

### One client per policy, not per service

Building a reqwest client loads the TLS roots. One per service made the unit tests run in
54 s rather than 10 s, and the proxy rebuilds its registry clients on each builder. A
`Connection` builds two clients when first asked, one for services without a credential
and one for those with, and its services share them. They differ only in the redirects
they follow, which is all a reqwest client holds per service.

### Kept to `src/service.rs`

`scripts/make/clients.py`, run by `make lint`, refuses `reqwest::Client`,
`reqwest::ClientBuilder` and `reqwest::get(` outside `src/service.rs` and `src/tls.rs`,
except in tests, so a request cannot bypass the declaration.

## The HEAD for a file's date

Before 2026-11-05 `Deciding::dated` sent a HEAD for a file's `Last-Modified` to the URL the
metadata named, wherever it was. The unservable check came after, so a publisher could name
a host and have the proxy ask it. `dated` is now given whether `fetch_plan` found the file
on an origin the proxy does not serve, and asks nothing then: the file is dated by its first
sighting, as one whose host sends no date is. An origin `BYRLE_ALLOW_DIRECT_ORIGINS` lists
is still asked, as the operator named it.
