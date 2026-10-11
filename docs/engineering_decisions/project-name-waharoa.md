# Project name: waharoa

- **Status:** Superseded 2026-10-01 by [project-name-byrle](project-name-byrle.md), after
  an informal cultural consultation. See "Consultation result" below.
- **Plan reference:** decision #13, and the plan header.

## Decision

`waharoa`, te reo Māori for the carved gateway of a pā, literally the long entrance.
Working name until the cultural consultation below is done.

## Rationale

Clean namespace. Verified Sept 2026 by direct exact-name lookup, which is definitive in
a way search is not: web search on this word returns noise. All four return 404:
`crates.io`, the npm registry, PyPI, and the `waharoa` GitHub org. Known-existing names
were queried in the same run and returned 200, so those 404s are real absences rather
than a broken probe.

## Outstanding gate

**Cultural consultation.** A waharoa is often the most significant carving on a marae,
so this is not neutral vocabulary. This needs someone with standing to advise. It is a
human conversation, not a lookup, and it is the remaining gate on the name.

It gates **release**, not development. Until then the name appears only in a binary
nobody outside this repository runs, so nothing built before launch depends on the
answer, and a "no" costs a find-and-replace plus rerunning the registry checks on the
replacement. It is scheduled in Stage 7, early enough that a rename is not competing with
the announcement.

## Consultation result

An informal cultural consultation on `waharoa` was held in September 2026, to get a first
reaction to the name. It was not a formal consultation. The person consulted:

- was not enthusiastic about the name.
- was concerned that the project has no Māori developers.
- said a name akin to Kaitiaki would fit better. Kaitiaki is heavily overloaded, so it
  is not a candidate as it stands.

A te reo Māori name would have to be asked for, given to the project, not chosen by it.
That request is not being made for this project now. It may be revisited if the project
gains support and local Māori engineers become involved. Until then the project is
`byrle`.

## Alternatives rejected

- **portcullis**: crowded in this exact neighbourhood. Docker ships a `portcullis`
  secrets-redaction library; `imjasonh/portcullis` verifies trust via Sigstore/Rekor
  before execution; Portcullis Labs is Cisco's EMEA security R&D arm. GitHub org taken.
- **waha** (the root word, mouth or entrance): `devlikeapro/waha` is an established
  self-hosted WhatsApp HTTP API distributed via Docker, with better SEO.
- **anything containing "-gate"**: the scandal suffix has gone international.
- **pkggate**: an existing OSS competitor.

Fallback shortlist if the consultation rules `waharoa` out: `ravelin`, `barmkin`,
`merlon`, `cordon`. Not `yett`: an npm package of that name exists, a third-party
script execution controller, uncomfortably adjacent. Confirmed by the same probe run.
