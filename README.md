# SOC-QA Intelligence

**Research Title**: *AI-Integrated SOC Triage Quality Assurance and Playbook Conformance Framework*  
**Research Direction**: *SOC Playbook Drift: Written Procedure vs. Actual Analyst Practice*

## Quick Start (Visual Studio Code Local Setup)

### 1. Backend Setup & Automated Tests
```bash
cd SOC-QA-Intelligence
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r backend/requirements.txt

# Run the automated verification test suite (7 end-to-end test suites)
PYTHONPATH=. python3 backend/tests/test_platform.py

# Seed initial reference playbooks (Phishing, T1110.003, T1059.001) & sample datasets
PYTHONPATH=. python3 scripts/seed_research_workspace.py

# Start the FastAPI server on http://localhost:8000 (Swagger UI at http://localhost:8000/docs)
PYTHONPATH=. uvicorn backend.app.main:app --reload --port 8000
```

### 2. Database Configuration (PostgreSQL or Local Fallback)
- **Option A — Docker PostgreSQL**: Run `docker compose up -d postgres` and set `USE_SQLITE_FALLBACK=false` in `.env`.
- **Option B — Zero-Config Local SQLite Fallback**: Enabled by default (`USE_SQLITE_FALLBACK=true`), storing all 27 relational tables in `./data/socqa_research.db` with full foreign-key enforcement.

### 3. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173` in your browser, or open the self-contained interactive workstation (`soc_qa_intelligence_workbench.html`) directly.
