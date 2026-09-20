# The PEP 503 HTML index is read, not forwarded

- **Status:** Implemented 2026-09-21. `src/ecosystem/pypi/html.rs`,
  `route::IndexFormat`, `pypi::rewrite::remove_from_html`.
- **Related:** [pypi-simple-index](pypi-simple-index.md),
  [pypi-index-filtering](pypi-index-filtering.md),
  [packument-tarball-url-rewriting](packument-tarball-url-rewriting.md)

## What was wrong

Only PEP 691 JSON was read. A body of any other type took the same branch as a tarball:
forwarded as a stream. Against an index that answers HTML that meant no filtering, no
rewriting, no records, and no `UNINSPECTED` line, because `uninspected()` reports only a
document the proxy meant to rewrite and could not.

Measured 2026-09-20 with the real binary, a stub HTML index and
`cooldown_days: 36500, install_scripts: block`:

```
$ pip install --index-url http://127.0.0.1:8124/simple/ idna
Successfully installed idna-3.10
```

The proxy's whole log for that install was two `proxied ... /simple/idna/ status=200` lines.
No `/packages/` request: pip took the wheel from `files.pythonhosted.org`, because the
`href`s still pointed there.

## Which indexes serve which form

Asked on 2026-09-21 for `application/vnd.pypi.simple.v1+json` and nothing else:

| Index | Answered |
|---|---|
| pypi.org, test.pypi.org | `application/vnd.pypi.simple.v1+json` |
| download.pytorch.org | `text/html` |
| pypi.nvidia.com | `text/html` |
| www.piwheels.org | `text/html` |
| data.pyg.org | `text/html` |

The four ignore `Accept` rather than refusing it: 200 with HTML, not 406. A `?format=`
query changes nothing. pypi.org, by contrast, answers `text/html` when asked for HTML, so
the negotiation works where it is implemented.

## Decision

`route::DocumentKind::SimpleIndex` carries the form, `IndexFormat::Json` or
`IndexFormat::Html`, and `pypi::html::parse` reads the page into the same `Project` the
JSON reader produces. Everything downstream, normalising, deciding, filtering and the
record store, is unchanged.

| Written as | Read as |
|---|---|
| `href` | the file's URL, resolved against the page's own URL |
| the fragment, `#sha256=<hex>` | the digest |
| the anchor's text | the filename |
| `data-yanked` | PEP 592: the reason, empty when the attribute has no value |
| `data-requires-python` | as written, entities turned back |
| `data-upload-time` | the publish time. PEP 503 has no field for it; download.pytorch.org writes it anyway |

It is a scanner over `<a>` elements, not an HTML parser. A page it cannot read is an error,
so the proxy forwards it and says `UNINSPECTED`, rather than reading it as a project with
no files, which would read as a package the index does not have.

## What this changed elsewhere

- `origin::reachable_path` keeps a URL's fragment. The rewrite replaces a whole quoted
  string, and in HTML that string is `URL#sha256=...`; dropping the fragment would take
  away the digest pip checks the bytes against.
- `pypi::classify_path` treats a file under `/simple/` as an artifact request.
  `www.piwheels.org` serves files from `/simple/<name>/<file>`, so the rewritten href
  points there and the request that follows has to be recognised as a file rather than as
  an index.
- A PEP 503 page has no name of its own, so the project is named by the page's URL, and by
  its filenames when the URL has no name in it either.

## The enforcement difference this leaves

A page with no `data-upload-time` gives records with no publish date, so `cooldown_days`
is unenforceable for every version from such an index. It is dropped and reported, never
passed silently: the audit log's event carries it.

```
pinned 3.10 action=block unenforceable=['cooldown_days', 'known_malware', 'kev', 'max_cvss']
```

An index on a different origin from its files needs that origin added with
`WAHAROA_ARTIFACT_ORIGINS`, or its files are left pointing at it: `download.pytorch.org`
writes `href`s on `download-r2.pytorch.org`, which the proxy does not front by default.

## Measured after the change

Same stub index, a denial of `pkg:pypi/idna@3.10`:

```
x-waharoa-filtered-versions: 1
x-waharoa-filtered-checks: denials
$ pip install --index-url http://127.0.0.1:8129/simple/ idna
ERROR: Could not find a version that satisfies the requirement idna (from versions: none)
```

With the version allowed, the file goes through the proxy and is verified:

```
INFO artifact requested, digest known path=/packages/76/c6/.../idna-3.10-py3-none-any.whl
INFO artifact digest verified path=/packages/76/c6/.../idna-3.10-py3-none-any.whl
```
