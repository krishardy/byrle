# Reading a packument without changing it

- **Status:** Implemented, Stage 1
- **Code:** `src/proxy.rs`, `src/http.rs`

## Decision

A packument response is buffered, decoded, and normalised from the decoded original.
Tarball responses stream through.

The forwarded document is then rewritten so artifact URLs point at the proxy, and
re-serialised. That decision, and why it reversed an earlier one, is in
[packument-tarball-url-rewriting.md](packument-tarball-url-rewriting.md); this file covers
reading the document, which is unchanged by it.

On a packument request the proxy replaces the client's `Accept-Encoding` with `gzip`,
or `identity` when the client does not accept gzip. A client that accepts neither keeps
its own header, and its body is not read.

Which document arrived is read from the response `Content-Type`, not from the request.

Decompression is capped, default 32 MiB, settable with `WAHAROA_MAX_PACKUMENT_BYTES`.
Past the cap the body is forwarded whole and not parsed.

## Rationale

**Why rewrite `Accept-Encoding`.** registry.npmjs.org answers brotli whenever br is
offered:

| `Accept-Encoding` sent | `Content-Encoding` returned |
|---|---|
| `gzip` | gzip |
| `gzip,deflate` | gzip |
| `gzip, deflate, br` | br |

npm 9.9.4 sends `gzip,deflate`, so npm alone would never produce a brotli body. Other
clients may offer br. Narrowing the request to gzip means one decompressor instead of
three, and the client still receives an encoding it listed.

**Why decode explicitly rather than letting reqwest do it.** reqwest's `gzip` feature is
off crate-wide, so nothing is decompressed behind the proxy's back and the proxy always
knows which bytes it holds. Forwarding a decompressed body under an unchanged
`Content-Encoding: gzip` would give the client a parse error that looks like the proxy's
bug, so whenever the body is re-serialised its `Content-Encoding` and `Content-Length` are
set to describe what is actually sent.

**Why the response decides which document it is.** npm asks with
`application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*`, which names
both documents. `PackumentDetail` qualifies every absent field on a record, so a wrong
label turns "nobody asked for a publish time" into "npm publishes no publish time".

**Why cap decompression.** gzip reaches about 5x on a packument (typescript: 2.0 MB
encoded, 15.7 MB decoded) and far more on crafted input. Without a ceiling the
decompressed size is chosen by whoever sent the body.

**Why normalise before forwarding rather than in a spawned task.** Stage 2 has to decide
before forwarding, so the shape does not change. A background task would also make the
`make smoke-npm` assertions racy. Measured cost: 2 ms for lodash (117 versions), 7 ms for
`@babel/core` (230), 252 ms for the full typescript packument (3,822 versions).

## Consequences

- An install never fails because the proxy could not inspect something. A body past the
  cap, in an encoding we do not decode, or in a shape we do not model is forwarded and
  logged. This is correct while there is no policy engine; Stage 2 has to revisit it,
  because a package that cannot be inspected is not a package that has been cleared.
- A warm npm cache sends `If-None-Match` and gets a 304 with no body, so the proxy
  observes no packument. The resolved graph is fully visible only on a cold cache. See
  the TODO item on fetching the packument on the proxy's own behalf.
- A buffered packument holds the encoded body and its decoded copy at once. Nothing yet
  bounds how many are buffered concurrently.
