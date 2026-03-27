# ATIRF v0.1.0 Public Preview

## Highlights
- ATT&CK catalog seeding and ATT&CK-linked detections
- ransomware playbook patterns and attack-pattern hypotheses
- optional live ransomware tracking through `ransomware.live`
- optional live CISA KEV ingestion
- optional live cybersecurity news aggregation across multiple public feeds
- optional local AI copilot through Ollama
- incident-type playbooks and decision-support helper
- saved analyst notes, tasks, and evidence records for local case handling
- user-defined CTI connector inventory
- improved public-facing dashboard and launch copy

## What This Release Is
This is the first public preview of ATIRF as an open cyber defense platform.

It is intended to show:
- the product direction
- the analyst workflow
- the ATT&CK and CTI foundation
- the community contribution model

## Positioning Note
ATIRF should be described as a distinct open workflow that brings together:

- ATT&CK-driven incident mapping
- CTI source integration
- ransomware and KEV awareness
- decision-support workflows
- local grounded AI through Ollama

The positioning should avoid unsupported claims that no adjacent platform exists.

## What This Release Is Not
- not a finished enterprise product
- not a replacement for a full SIEM/SOAR stack
- not validated for production threat detection at scale

## Recommended Demo Flow
1. Seed ATT&CK + CTI
2. Load Showcase Data
3. Refresh the live ransomware feed if enabled
4. Select an incident
5. Generate an Ollama-backed local copilot analysis if enabled

## Known Constraints
- external live feed behavior depends on your local network and source availability
- public ransomware-victim feeds should be treated as enrichment, not ground truth
- Ollama must be running locally for live copilot output
