# Architecture Overview

## Components
- FastAPI backend
- SQLite demo datastore
- Static dashboard
- Detection and scoring services
- Correlation logic
- Summarization engine

## Production Upgrade Path
- PostgreSQL for relational data
- OpenSearch for search and log analytics
- Redis/Celery for async jobs
- SSO / OIDC integration
- Secrets vault
- External LLM or local model with retrieval grounding
- Real connectors for EDR, M365, firewalls, TI platforms
