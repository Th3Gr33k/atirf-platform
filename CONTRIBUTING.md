# Contributing to ATIRF

ATIRF is intended to be built in the open with defenders, researchers, and engineers who want to improve practical cyber defense tooling.

## High-Value Contributions
- ATT&CK mappings and detection improvements
- CTI connector implementations
- sample datasets and replay scenarios
- incident workflow improvements
- UI and analyst usability improvements
- tests, bug reports, and documentation

## Before You Contribute
1. Open an issue or start a discussion for larger changes.
2. Keep changes focused and explain the defender value.
3. Add or update tests when behavior changes.
4. Document any new env vars, routes, or workflows.

## Development
```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest -q
python -m uvicorn app.main:app --reload
```

## Pull Request Expectations
- explain the problem clearly
- summarize the approach
- call out security or detection tradeoffs
- include screenshots for UI changes
- avoid unrelated cleanup in the same PR
