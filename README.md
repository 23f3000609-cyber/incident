# Observable Incident Triage — grading-contract implementation

FastAPI + SQLite + OpenRouter-compatible model endpoint. It implements the required routes:

- `POST /v2/incidents`
- `POST /v2/incidents/{runId}/receipts`
- `GET /v2/incidents/{runId}`

## Local run

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
copy .env.example .env   # Windows; manually edit values
uvicorn main:app --reload --port 8000
```

Set `OPENROUTER_API_KEY`, `OPENROUTER_MODEL` and `DB_PATH`. The model is called once per first-seen run ID; receipts and GET/replay do not call it.

## Railway deployment

1. Push this directory to a GitHub repository.
2. In Railway, create a project from that repository. The included Dockerfile is used.
3. Add variables:
   - `OPENROUTER_API_KEY` = your OpenRouter API key
   - `OPENROUTER_MODEL` = a low-cost model supported by your account, e.g. `openrouter/auto`
   - `PUBLIC_BASE_URL` = the Railway public HTTPS domain
   - `DB_PATH` = `/data/incidents.sqlite3`
4. Add a Railway Volume mounted at `/data`; SQLite persistence depends on this.
5. Generate a public domain, wait for deployment, then verify `https://YOUR-DOMAIN/health` returns `{"ok":true,...}`.
6. Submit only the base URL, without a path, query string, fragment, or credentials.

## Important verification

Run `pytest -q`. Then test on Railway using the grader's Check endpoint before Save. Each Check and Save consumes one of the ten checks per 24 hours; Save only the most recent run counts. Do not spend the final available check on debugging.

## Contract notes

The server validates profile, evidence IDs, catalog tool names, receipt correlation, idempotency, destructive approval, and changed-content conflicts. Tool outcomes are treated as authoritative receipts; this server does not execute real production tools.

**Before submission:** inspect every grader feedback category. Some grading environments require exact tool argument schemas/decision choices, so test with the supplied grader and fix any feedback rather than assuming a local happy-path test proves full credit.
