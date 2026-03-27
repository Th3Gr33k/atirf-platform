# ATIRF — Adaptive Threat Intelligence & Response Framework
![Status](https://img.shields.io/badge/status-experimental-orange)
![Build](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![Focus](https://img.shields.io/badge/focus-AI%20%2B%20Cybersecurity-purple)
![Stage](https://img.shields.io/badge/stage-active%20development-yellow)

> AI-assisted cybersecurity platform for detection, correlation, and response  
> Built for defenders. Designed for reality. Still evolving.
> Turning raw telemetry into actionable intelligence with explainable AI.

---

## 🚧 Project Status - Work in Progress / Experimental

ATIRF is currently a **work in progress** and should be considered **experimental**.

This platform is under active development as I continue refining:

- Detection logic and correlation capabilities  
- Threat intelligence enrichment workflows  
- AI-assisted triage and explainability  
- System architecture and integrations  

The goal is to build something **practical, modular, and meaningful for cyber defenders worldwide**.

> I would genuinely appreciate feedback, ideas, contributions, and support from the cybersecurity and AI community.

---
## Why This Matters

Cybersecurity is shifting from tool-centric detection to **intelligence-driven decision making**.

Defenders today face:
- Alert fatigue
- Fragmented telemetry
- Limited context during triage
- Increasingly intelligent adversaries

ATIRF is an attempt to solve this by combining:
- Detection
- Threat intelligence
- Correlation
- Explainable AI assistance

Into a **single analyst-centric workflow**.

---

## 🎯 What is ATIRF?

ATIRF (Adaptive Threat Intelligence & Response Framework) is a **modular cyber defense platform** designed to:

- Ingest multi-source telemetry  
- Enrich events with threat intelligence  
- Detect suspicious behavior  
- Correlate events into incidents  
- Produce **explainable, analyst-ready outputs**  

This is not just a concept—this repository includes a **working demo system**.

---

## ⚙️ Current Implementation

This repository includes a **functional demo platform** built with:

- **FastAPI** backend  
- **SQLite** (via SQLAlchemy) for portability  
- **Static HTML/JavaScript dashboard**  
- **Rule-based detection engine**  
- **Explainable AI-style summarization (deterministic)**  
- **Docker Compose deployment**  
- **Sample telemetry datasets**

---

## 🧠 Key Features

- Multi-source telemetry ingestion  
- Threat intelligence enrichment  
- MITRE ATT&CK mapping  
- AI-assisted incident analysis (explainable)  
- Risk scoring and event correlation  
- Analyst-centric case workflow  
- Portable demo environment  

---

## 🏗️ Architecture

![Architecture](docs/architecture.png)

---

## 🎥 Demo Capabilities

- Load realistic sample telemetry  
- Observe detection and alert generation  
- View correlated incidents  
- Analyze explainable AI-style summaries  
- Explore ATT&CK mappings and risk scoring  

---

## 🚀 Quick Start

```bash
docker compose up --build
````

Then open:

* Dashboard → [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
* API Docs → [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## 🎯 Goals

* Provide an **analyst-centric detection and triage workflow**
* Demonstrate **explainable AI assistance** without replacing humans
* Deliver a **practical, portable blueprint** for defenders
* Enable future integrations with:

  * EDR/XDR
  * SIEM platforms
  * Firewalls
  * Email security
  * Threat intelligence platforms

---

## 🔍 Demo Scenario

The included dataset simulates a realistic attack chain:

1. Microsoft Word spawns PowerShell
2. PowerShell executes an encoded command
3. Endpoint connects to a newly observed domain
4. Domain has poor reputation
5. Risk score increases based on behavior + context
6. Events are correlated into a single incident
7. System generates an **explainable analyst summary + recommended actions**

---

## 📦 Repository Structure

```text
atirf-platform/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── models/
│   │   ├── services/
│   │   ├── static/
│   │   ├── database.py
│   │   ├── main.py
│   │   └── schemas.py
│   ├── tests/
│   └── requirements.txt
├── data/
│   └── sample_logs/
├── docs/
├── docker/
├── scripts/
├── docker-compose.yml
└── README.md
```

---

## 📡 API Overview

* `GET /api/health` → Health check
* `POST /api/events/ingest` → Ingest event
* `POST /api/events/bulk` → Bulk ingest
* `GET /api/events` → List events
* `GET /api/alerts` → Alerts
* `GET /api/incidents` → Correlated incidents
* `GET /api/metrics` → Metrics
* `POST /api/demo/load` → Load demo dataset

---

## 📊 Risk Scoring Model

Transparent and explainable:

```text
Risk Score = Base Severity + Asset Criticality + IOC Reputation + Behavioral Indicators + Novelty
```

Designed to be:

* understandable
* tunable
* extensible

---

## 🛡️ Detection Logic (Current)

* Encoded PowerShell execution
* Office spawning script engines
* Suspicious domain communication
* Admin activity on critical assets
* Multi-event correlation (attack chain detection)

---

## 🤖 AI / Explainability Layer

This demo intentionally avoids external LLM dependency.

Instead, it provides:

* Deterministic, explainable incident summaries
* Analyst-readable reasoning
* Transparent logic

Future roadmap includes:

* LLM-assisted triage
* Retrieval-augmented analysis
* Natural language querying
* Threat narrative generation

---

## 🔐 Security Considerations

This is a **demo blueprint**. For production use, implement:

* RBAC and SSO
* API authentication/authorization
* Secrets management
* Queue-based processing
* Secure logging
* LLM safety controls (prompt injection, output validation)

---

## 🌍 Intended Audience

* SOC Analysts
* Security Engineers
* Threat Intelligence Teams
* AI Security Practitioners
* MSSPs
* Blue Teams
* Cybersecurity Researchers

---

## 👤 Author

**Mr. Gr33k H4sh3r - AKA Deiker**
A Cybersecurity lead that love cyber and AI :)

---

## 🤝 Contributing / Community 

This project is being built **in the open**.

If you're in:

* blue team
* threat intel
* AI security
* detection engineering

Your feedback matters.

> Suggestions, ideas, critiques, and contributions are all welcome.

---

## ⭐ Vision

> Build a practical, explainable, and globally accessible platform that helps defenders make better decisions—not just detect more alerts.
 
 ---