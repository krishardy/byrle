# `latest` naming a removed npm version moves to the highest release below it

- **Number:** 0144
- **Status:** Implemented 2026-11-25. `src/ecosystem/npm/rewrite.rs` (`latest_after`).
- **Amends:** [enforcement-tiers](0019-enforcement-tiers.md), which dropped every
  `dist-tags` entry naming a removed version.

## Decision

When the proxy removes the version `dist-tags.latest` names, `latest` is rewritten to the
highest version that remains, is not a prerelease, and is below the removed one. With no
such version, `latest` is dropped. Any other tag naming a removed version is dropped, as
before.

## Why

On 2026-11-25, `cooldown_days: 7` removed `@anthropic-ai/sdk` 1.11.0 to 1.14.0, and
`latest` named 1.14.0. The proxy served `"dist-tags": {"alpha": "0.34.0-alpha.0"}`.

| Command, through the proxy | Before |
|---|---|
| `npm view @anthropic-ai/sdk versions` | printed nothing, exit 0 |
| `pnpm view @anthropic-ai/sdk versions` (pnpm 10.33.0 runs npm's `view`) | printed nothing, exit 0 |
| `npm view @anthropic-ai/sdk@1.10.0 version` | `1.10.0` |

`npm view <name>` means `<name>@latest`, and reads the tag. 0019 expected the resolver to
fall back when the tag is gone. That holds for a range such as `^1.0.0`, but not for a
command that asks for the tag.

npm's registry does the same when the version `latest` names is unpublished: `latest`
moves to a version that remains.

## Choices

- **Below the removed version, not the highest overall.** A package can publish a major
  version without tagging it `latest`. The highest release below the old `latest` keeps
  the maintainer's line.
- **Releases only.** `1.1.0-rc.1` is not taken for `latest`, as npm does not tag
  prereleases `latest` by default.
- **A version that is not semver is skipped**, and a `latest` that is not semver is
  dropped, because there is no order to pick by.
