# PyPI simple-index fixtures

Real entries from `https://pypi.org/simple/requests/`, fetched 2026-09-16 with
`Accept: application/vnd.pypi.simple.v1+json` (PEP 691, `api-version: 1.4`). Byte for byte
as the index served them, with the file list cut to the three shapes below. The full
document was 123,104 bytes: 244 files for 160 versions.

| File | Shape | Read as |
|---|---|---|
| `requests-0.2.0.tar.gz` | sdist, no `requires-python`, no `core-metadata` | `Kind::Sdist`, version `0.2.0` |
| `requests-2.34.2-py3-none-any.whl` | wheel, `requires-python`, PEP 658 `core-metadata`, PEP 740 `provenance` | `Kind::Wheel`, version `2.34.2` |
| `requests-2.32.0-py3-none-any.whl` | **yanked with a reason string**, PEP 592 | `yanked: true` |

The yanked entry is the reason `yanked` is read as "not `false`" rather than as a boolean:
PEP 592 allows either `false` or a string giving the reason, and this one carries
`"Yanked due to conflicts with CVE-2024-35195 mitigation"`.

To refresh, take the same entries from a newer index. Do not hand-edit them: an entry PyPI
would never serve tests nothing.
