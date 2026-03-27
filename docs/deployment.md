# Deployment Guide

## Local Deployment
1. Create a Python virtual environment
2. Install requirements
3. Launch `python -m uvicorn app.main:app --reload` from `backend`
4. Open `http://127.0.0.1:8000/`
5. Use `Load Demo Data` or `Load Showcase Data` in the dashboard
6. Use `http://127.0.0.1:8000/docs` for API exploration
7. Click `Seed ATT&CK + CTI` to populate the ATT&CK catalog and ransomware hypothesis panels
8. Optionally enable Ollama and use `Generate Incident Analysis` for grounded local-AI output
9. Optionally enable `ransomware.live` to populate the live ransomware tracking panels
10. KEV and cyber news panels are enabled by default and will populate when network access is available

## Local Validation

```bash
cd backend
pytest -q
```

The current automated checks validate:

- health and readiness
- alert and incident creation from ingest
- demo dataset loading and metrics population
- ATT&CK seeding, CTI connector creation, and attack-pattern hypothesis generation
- grounded copilot endpoint behavior when Ollama is disabled
- live ransomware feed endpoint behavior when the source is disabled
- workflow persistence, connector sync, and local event import helpers

## Practical Local Workflow
1. Start the platform locally
2. Seed ATT&CK + CTI
3. Load showcase data or import a local JSON file
4. Review incidents and hypotheses
5. Use the playbook and decision helper
6. Save workflow state
7. Add connectors and run connector sync
8. Review connector job history to confirm execution results

## Docker Deployment
Run:

```bash
docker compose up --build
```

## Production Considerations
- Replace SQLite
- Add authn/authz
- Move to TLS
- Separate API and UI containers
- Add worker queues
- Harden logging, secrets, and alert actions
- Disable demo routes and enable API key or OIDC protection
