# ai-alert-triage

Security teams receive more alerts than they can review by hand. AI Alert Triage is a Python service that receives security alerts through a webhook, uses a Large Language Model to classify each one by severity and summarize it for an analyst, and stores the result for querying.

For high and critical alerts, a read-only investigation agent gathers context from identity, endpoint and network sources (Okta, SentinelOne and Zscaler, mocked behind the same contracts as their real APIs), maps the activity to MITRE ATT&CK techniques and writes an incident report with the evidence it used and suggested next steps. The agent never takes response actions on its own.

**Built with security in mind**
- OAuth2/OIDC with Okta: JWT validation against the provider's JWKS and scope-based access
- Sensitive data redacted before any content reaches the LLM
- Alert content treated as untrusted input, with defenses against prompt injection
- Audit log of every LLM call: input, model, output and cost
- Pluggable LLM providers (OpenAI and Azure OpenAI) behind a single intssumed:** triage accuracy is evaluated against a labeled set of alerts, and the results are published in this README.

**Stack:** Python 3.12, FastAPI, Pydantic, PostgreSQL, SQLAlchemy, Alembic, pytest, Docker, GitHub Actions. Hexagonal architecture (ports and adapters).
