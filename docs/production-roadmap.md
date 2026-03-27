# ATIRF Production Roadmap

## Phase 0: Credible Open Demo
- stable local deployment
- richer public demo datasets
- screenshot-ready analyst console
- API tests for ingest, metrics, and incidents

## Phase 1: Production Foundation
- environment-based configuration
- PostgreSQL support
- schema migrations with Alembic
- authn and RBAC
- audit logging and request tracing
- structured application logging
- health and readiness probes
- CI for tests and linting

## Phase 2: Detection Platform
- canonical event schema with source mappings
- versioned detection rules
- rule unit tests and replay tests
- false-positive annotations
- suppression and exception workflow
- ATT&CK and data-source coverage tracking
- ATT&CK ingestion from official STIX/TAXII sources

## Phase 3: Investigation Platform
- entity graph for users, hosts, IPs, hashes, domains, and identities
- time-windowed correlation
- evidence records and chain-of-custody metadata
- case assignment, notes, and status workflow
- analyst timelines and pivoting

## Phase 4: Response and Intelligence
- connectors for EDR, M365, identity, DNS, proxy, firewall, and TI providers
- approval-based response actions
- intel sightings and campaign tracking
- premium research feed
- Ollama-backed local AI copilot for grounded incident reasoning

## Phase 5: Commercial Operations
- multi-tenant control plane
- billing and customer isolation
- MSSP mode
- reporting packs
- executive dashboards
- compliance evidence exports

## Technical North Star
The long-term target architecture should include:

- FastAPI or equivalent API layer
- PostgreSQL for transactional data
- OpenSearch for search and analytics
- Redis-backed task queue
- object storage for evidence artifacts
- worker services for enrichment and response jobs
- OIDC-based identity
- tenant-aware authorization
- local or self-hosted model runtime through Ollama for open-weight model support
