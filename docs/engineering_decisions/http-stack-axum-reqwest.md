# HTTP stack: axum server-side, reqwest upstream

- **Status:** Decided
- **Plan reference:** decision #12

## Decision

axum server-side, reqwest upstream. **No fetch trait in Stage 1**; the boundary is
extracted in Stage 2 or 3 against real callers.

## Rationale


**axum server-side, reqwest upstream.** Both are hyper underneath with the missing
pieces filled in, and since a proxy runs both halves in the same process, sharing a
hyper version and body types means an upstream stream flows into the response without
conversion.

The asymmetry that decides it: hyper's server side is reasonably complete (framing,
keep-alive, HTTP/2; you supply routing and middleware, which is what axum adds), but
hyper's client side hands you a *connection*, not a client. DNS, TLS setup, connection
pooling and redirect handling would all be ours to own. That is not work a security
tool wants to take on to gain control it may not need.

**Not a lock-in.** The two sides are independent. Replacing the upstream client never
touches axum, which does not know what fetches for it. And reqwest's response body
converts into a hyper-compatible stream, so the hashing wrapper is the same code either
way; a swap adds pooling via `hyper-util` plus redirects, contained in one module.

**No fetch trait in Stage 1. Call reqwest concretely** and extract the boundary in
Stage 2 or 3, against real callers, on the same schedule as the adapter trait.

> **Reversed, Sept 2026.** This section previously argued for a narrow trait
> (*packument by name*, *body stream by URL*) from day one, on the grounds that both
> shapes were already known and the surface was three methods rather than a whole
> protocol, so the Stage 3 reasoning for deferring the *adapter* abstraction did not
> apply. That argument does not hold, and it is weakest exactly where it matters most.
> A single body-stream signature has to serve all three branches of the fetch path
> below: cache-hit streams through, novel-and-cheap buffers, novel-and-expensive defers
> with a 429. None of those exist yet, so the method would be designed against zero
> callers. That is the failure the adapter deferral exists to prevent, and Stage 1 is
> not exempt from its own rule.

The swap cost this was meant to buy stays low regardless, for the reason given above:
axum does not know what fetches for it, so replacing the upstream client never touches
the server side, and the hashing wrapper is the same code either way.

**This makes the testing approach load-bearing**, since there is no seam to inject a
fake through. Stage 1 wants HTTP-level fixtures rather than a stubbed client, which for
a proxy is the better target anyway: the bytes on the wire are the product, and a fake
that speaks Rust types would skip the part most likely to be wrong.

Streaming works cleanly in axum: its response body is just an `http-body`
implementation, so it forwards chunks as they arrive without buffering, and the hashing
wrapper sits in that chain naturally.

