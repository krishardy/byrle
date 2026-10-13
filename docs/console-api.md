# Console API

Under `BYRLE_CONSOLE_URL`'s path, such as `https://byrle.example.com/admin/api/v1/`. Each
request is from a session, by the `byrle_session` cookie a login sets, or from a proxy
token in any form the proxy takes. A session request that changes something sends
`X-Byrle-CSRF`, the `csrf` the login returned.

The OpenAPI 3.1 document, generated from the code that answers each request, is served at
`api/v1/openapi.json` and kept in `tests/fixtures/console/openapi.json`; it gives each
parameter and body ([console-openapi](engineering_decisions/console-openapi.md)). A test
holds this table to the routes the console answers.

| Method | Path | Needs | Answers |
|---|---|---|---|
| GET | `api/v1/health` | nothing | `{"status":"up"}`, or 503 with the components not up |
| GET | `api/v1/openapi.json` | nothing | the OpenAPI document |
| POST | `api/v1/login` | nothing | `{"account","password"}` for a session cookie and its CSRF token |
| POST | `api/v1/logout` | a session | ends it |
| GET | `api/v1/session` | a session or token | who the caller is |
| GET | `api/v1/accounts` | `accounts.read` | each account and its roles |
| GET | `api/v1/dependencies` | `requests.read` | versions served to each account, R3 |
| GET | `api/v1/alerts` | `alerts.read` | versions served before a malware advisory named them, R4 |
| GET | `api/v1/requests` | `requests.read` | audit log lines, filtered; R5 is `answered=refused&check=known_malware`, R9 |
| GET | `api/v1/metrics/failures` | `requests.read` | failures by hour and case, R6 |
| GET | `api/v1/config` | `config.read` | the configuration, secrets removed, R7 |
| GET | `api/v1/events` | `events.read` | the account event log, R8 |
| GET | `api/v1/logs/{day}` | `requests.read` | a UTC day of the audit log as written, NDJSON, R9 |
| GET | `api/v1/status` | `status.read` | each component's status, R10 |

`admin` holds every permission ([admin-plan](admin-plan.md) §4.2). The web interface's
pages need the same permissions as the endpoints they show.
