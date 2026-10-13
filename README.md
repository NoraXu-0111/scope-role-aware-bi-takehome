# Scope: role-aware conversational BI

Scope is a local demo over a fictional fraud-operations warehouse. The task brief is in [TASK.md](TASK.md); the scorecard, design decisions, and limitations are in [NOTES.md](NOTES.md).

## Run

Python 3.11 and Node 20+ are recommended. Set `OPENAI_API_KEY` in the environment or a local `.env` file. Never commit the key.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python seed.py
cd web && npm ci && npm run build && cd ..
.venv/bin/uvicorn api.main:app --host 127.0.0.1 --port 8765
```

Open <http://127.0.0.1:8765>. Choose a demonstration identity, ask a question, then ask a follow-up. A chart request uses an approved query result. Changing identity or starting a new conversation clears the prior conversation and results. The identity picker is for this local demo, not production authentication.

## Verify

```bash
.venv/bin/pytest -q
.venv/bin/python eval/run_eval.py --only leaks
.venv/bin/python eval/run_eval.py --ids f1,f2,f3
.venv/bin/python eval/run_eval.py --report artifacts/eval.json
cd web && npm run build && npx playwright test
```

Playwright expects the API server above to be running on port 8765. The full evaluation calls the model and uses the configured API key. The saved [artifacts/eval.txt](artifacts/eval.txt) and [artifacts/eval.json](artifacts/eval.json) are the completed expanded run: **25/25 correctness and 24/24 access clean**, including three multi-turn follow-ups. See [NOTES.md](NOTES.md) for commands, measurements, and the earlier model-service interruption.

## Deliverables

- The `submission` Git branch, also exported as [artifacts/submission.bundle](artifacts/submission.bundle) for transfer without a remote.
- [NOTES.md](NOTES.md): scorecard, architecture, audit, cost, AI log, and omissions.
- [artifacts/walkthrough.webm](artifacts/walkthrough.webm): recorded walkthrough of the live interface and solution architecture. Browser screenshots are alongside it.
- `agent/`, `api/`, `web/`, `eval/`, and `tests/`: implementation and extended evaluation.

The private per-turn audit file is `.runtime/audit.jsonl` (created with owner-only permissions). The browser shows a limited query trace and audit reference; raw released rows stay in the private record.
