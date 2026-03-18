# Multi-Agent Cybersecurity System

A production-ready, full-stack cybersecurity monitoring platform powered by 5 collaborative AI agents.

## Features
- **Hunter Agent** – Statistical, ML (Isolation Forest + Random Forest), and rule-based anomaly detection
- **Analyst Agent** – GPT-4 threat analysis with SHAP explainability  
- **Responder Agent** – Automated action recommendations by risk level
- **Reporter Agent** – Real-time metrics, charts, and executive reports
- **Watchdog Agent** – Monitors agent behaviour for meta-anomalies
- **7-page Streamlit Dashboard** – Live monitoring, chat, incident details, explainability, reports
- **FastAPI REST API** – Full OpenAPI/Swagger documentation

## Quick Start

```bash
# 1. Clone & enter directory
cd ultraviolet-granule

# 2. Copy env and add your OpenAI key
cp .env.example .env
# Edit .env → set OPENAI_API_KEY

# 3. Install dependencies
pip install -r requirements.txt

# 4. Generate synthetic data & train models
python src/data/log_generator.py
python src/ml/trainer.py

# 5. Start API server
uvicorn src.api.main:app --reload --port 8000

# 6. Start Streamlit dashboard (new terminal)
streamlit run src/frontend/app.py --server.port 8501
```

**Or with Docker:**
```bash
cp .env.example .env  # edit OPENAI_API_KEY
docker-compose up --build
```

Then open:
- Dashboard: http://localhost:8501
- API Docs: http://localhost:8000/docs

## Project Structure
```
├── src/
│   ├── agents/          # 5 AI agents + orchestrator
│   ├── api/             # FastAPI backend + routers
│   ├── data/            # Log generator & parser
│   ├── database/        # SQLAlchemy models
│   ├── frontend/        # Streamlit app (7 pages)
│   └── ml/              # ML models + SHAP
├── data/                # Generated logs & SQLite DB
├── models/              # Trained ML models (joblib)
├── tests/               # pytest tests
└── logs/                # System audit logs
```

## Tech Stack
Python 3.11 · FastAPI · Streamlit · scikit-learn · OpenAI GPT-4 · SQLAlchemy · SQLite · Plotly · SHAP · Docker
# cybershield-ai
