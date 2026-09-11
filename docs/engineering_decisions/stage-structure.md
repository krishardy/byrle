# Stage structure: split transport from policy

- **Status:** Staging
- **Plan reference:** decision #9

## Decision

The former M0 spike is dissolved. M1 is a pass-through proxy (transport only), M2 is the
decision layer (policy and intel).

## Rationale

The reverse proxy is well-understood architecture plus certificate management, not a
research risk, so it did not need a spike to prove. M1's exit criterion subsumes what
the spike would have demonstrated.

Splitting on the transport/policy boundary makes M1 falsifiable without any policy
logic: a wrong PURL surfaces as a wrong PURL rather than as a mysterious verdict, so
identity bugs are found before evaluation logic exists to confuse them with.

## Consequences

M1 ships with no policy at all. The throwaway hardcoded block added in Stage 1 exists
only to prove interception, is env-only with no config behind it, and is replaced
wholesale in Stage 2.
