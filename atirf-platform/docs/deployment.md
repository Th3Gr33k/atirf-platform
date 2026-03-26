# Deployment Guide

## Local Deployment
1. Create a Python virtual environment
2. Install requirements
3. Launch `python -m app.main` from `backend`
4. Open `http://127.0.0.1:8000/`
5. Use the dashboard buttons to reset and load demo data

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
