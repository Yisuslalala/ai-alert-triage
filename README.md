# ai-alert-triage

![CI](https://github.com/Yisuslalala/ai-alert-triage/actions/workflows/ci.yml/badge.svg)

Security teams receive more alerts than they can review by hand. AI Alert Triage is a Python service that receives security alerts through a webhook, uses a Large Language Model to classify each one by severity and summarize it for an analyst, and stores the result for querying.

For high and critical alerts, a read-only investigation agent gathers context from identity, endpoint and network sources (Okta, SentinelOne and Zscaler, mocked behind the same contracts as their real APIs), maps the activity to MITRE ATT&CK techniques and writes an incident report with the evidence it used and suggested next steps. The agent never takes response actions on its own.

**Built with security in mind**
- OAuth2/OIDC with Okta or Entra ID: JWT validation against the provider's JWKS and scope-based access
- Sensitive data redacted before any content reaches the LLM
- Alert content and tool output treated as untrusted input, with defenses against prompt injection
- Audit log of every LLM call: input, model, output, tokens and cost
- Pluggable LLM providers (OpenAI and Azure OpenAI) behind a single interface
- CI on every push: lint, strict type checking, tests against Postgres, dependency vulnerability audit and Docker build

**Stack:** Python 3.14, FastAPI, Pydantic, PostgreSQL, SQLAlchemy, Alembic, PyJWT, pytest, Docker, GitHub Actions. Hexagonal architecture (ports and adapters).

## How it works

```
POST /alerts ──► redact ──► classify (LLM or keywords) ──► store ──► 201 + severity
                                                              │
                                    high / critical ──► background investigation
                                                              │
        LLM agent ◄──► read-only tools: Okta user + System Log, SentinelOne agent + threats,
                       Zscaler URL lookup
                                                              │
                     incident report (summary, ATT&CK techniques, evidence, next steps)
                                                              ▼
                                               GET /alerts/{id}/report
```

### Investigation agent guardrails

| Risk | Control |
| --- | --- |
| Agent changes something in production | Every tool is read-only; no port exists for response actions |
| PII sent to the LLM | The model sees handles like `user_1`; code resolves them to real values, and tool output is redacted before it goes back to the model |
| Agent steered into querying arbitrary users or hosts | It can only use entity handles extracted from the alert itself |
| Prompt injection in the alert or tool output | Content is wrapped in tags with a random nonce, and the system prompt treats it as data |
| Invented ATT&CK techniques or evidence | Technique IDs are restricted to a catalog by the JSON schema; evidence is recorded by code from real tool calls |
| Runaway loops | Bounded steps; the last step's schema only allows `finish` |
| No traceability | Every LLM call is written to the JSONL audit log with token count and cost |

## Run it

```bash
cp .env.example .env            # set LLM_PROVIDER=openai|azure and keys for the LLM path
docker compose up --build       # Postgres + API on http://127.0.0.1:8000 (auth disabled locally)

curl -X POST http://127.0.0.1:8000/alerts -H 'Content-Type: application/json' -d '{
  "source": "sentinelone",
  "title": "Encoded PowerShell after suspicious sign-in",
  "description": "invoice_0923.ps1 executed from Downloads",
  "raw_payload": {"user": "j.doe@example.com", "hostname": "WS-0142", "url": "update-microsoft-cdn.com"}
}'
curl http://127.0.0.1:8000/alerts/<alert_id>/report
```

With `LLM_PROVIDER=keyword` (the default), alerts are triaged by keyword rules and no LLM or investigation is used.

To require tokens, set `AUTH_ISSUER`, `AUTH_AUDIENCE` and `AUTH_JWKS_URL` (for example, an Okta custom authorization server) and grant clients the `alerts:write` or `alerts:read` scopes.

## API

| Method | Path | Scope | Description |
| --- | --- | --- | --- |
| GET | `/health` | none | Liveness check |
| POST | `/alerts` | `alerts:write` | Receive and triage an alert; high and critical alerts are investigated |
| GET | `/alerts/{id}` | `alerts:read` | Triage result |
| GET | `/alerts/{id}/report` | `alerts:read` | Incident report from the investigation agent |

## Development

```bash
uv sync
uv run pytest                   # Postgres tests run when TEST_DATABASE_URL is set
uv run ruff check . && uv run mypy src tests
```
