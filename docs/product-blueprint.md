# ATIRF Product Blueprint

## Positioning
ATIRF should be positioned as an open cyber defense platform focused on:

- detection engineering
- explainable incident reasoning
- portable deployment for defenders, researchers, and MSSPs
- local-first open AI for grounded cyber analysis

The product should avoid competing head-on as a generic SIEM. The stronger position is:

> open detection and incident intelligence fabric with a premium operational layer

## Product Thesis
Security teams do not need more raw alerts. They need:

- normalized evidence
- explainable detections
- entity-aware correlation
- guided analyst workflows
- portable deployment models

ATIRF should turn fragmented telemetry into defensible, evidence-linked incidents with clear reasoning and next actions.

## Target Users
- blue teams and threat hunters
- small and mid-sized SOCs
- MSSPs and MDR teams
- cyber research communities
- training labs and universities

## Open Source Core
The open-source edition should build trust and community adoption.

Core capabilities:
- normalized event schema
- ingestion API and replay tooling
- detection-as-code engine
- ATT&CK-mapped open rule packs
- explainable scoring and rationale
- local correlation engine
- analyst-ready incident summaries
- demo datasets and lab deployment
- optional local AI via Ollama-hosted open models

Community assets:
- public rule tests
- detection coverage maps
- ATT&CK-aligned scenarios
- adversary emulation packs
- tuning notes and false-positive guidance

## Commercial Layer
The paid product should monetize operational value, not artificially hide the core.

Commercial capabilities:
- hosted multi-tenant control plane
- MSSP tenant segregation and customer workspaces
- premium connectors and managed ingestion pipelines
- managed threat intelligence enrichment
- case management, assignment, SLA, and reporting
- response orchestration with approval workflows
- premium research packs and continuous rule updates
- executive dashboards and compliance evidence exports
- grounded analyst copilot and response drafting

## AI Strategy
ATIRF should prefer a grounded, local-first AI architecture.

Recommended default path:
- Ollama for local model serving
- open-weight models for summarization and reasoning
- retrieval over internal evidence, ATT&CK data, CTI, and incident context
- deterministic detection and correlation before any LLM interpretation

AI should never be the source of truth.
It should explain, rank, summarize, and recommend based on evidence already in the platform.

## Community Purpose
ATIRF should explicitly invite defender participation.

The project should aim to become a community-built platform where contributors can:
- add detections
- validate mappings
- expand CTI connectors
- contribute public datasets
- improve analyst workflows
- pressure-test the platform in real defensive use cases

## Differentiation
ATIRF should be recognized for four things:

1. Explainable security reasoning
Every incident summary should cite the exact evidence, rules, ATT&CK mappings, confidence, and recommended steps.

2. Open detection credibility
Rules, tests, datasets, and ATT&CK mappings should be public and versioned.

3. Portable deployment
Support self-hosted, sovereign, air-gapped, and hosted models without changing the analyst workflow.

4. Threat-chain reconstruction
The user experience should emphasize adversary progression across entities and time rather than isolated alerts.

## Recommended Packaging
Open source:
- ATIRF Community

Commercial:
- ATIRF Cloud
- ATIRF Enterprise
- ATIRF MSSP

## Revenue Model
- per-tenant subscription for hosted deployments
- volume tiers by monitored assets or daily ingested events
- premium research feed subscription
- MSSP licensing with workspace-based pricing
- services for deployment, content engineering, and threat research

## Go-To-Market
Phase 1:
- build public credibility through GitHub, research blogs, demo videos, ATT&CK-aligned detections, and lab content

Phase 2:
- recruit design partners among small SOCs, consultancies, and MSSPs

Phase 3:
- release hosted premium features with migration path from community edition

## Why This Can Be Unique
Most projects expose alerts and call that AI. ATIRF should instead provide:

- evidence-first incident reasoning
- defender-centric investigation flow
- reproducible detection research
- open trust with premium operations
