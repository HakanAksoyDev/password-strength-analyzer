# Password Strength Analyzer 🔐

Production-safe web app + CLI for password strength analysis, built from the original academic project.

## What this project is

This repository provides:

- **Web app (public deploy)**: password strength analysis only
- **CLI (local academic usage)**: analyzer plus optional classroom demos

The core scoring logic is reused from `src/analyzer.py` (not reimplemented separately for web).

## Public web version scope

The public deployment exposes only:

- `GET /api/health`
- `POST /api/analyze`
- static single-page UI in `public/`

It does **not** expose brute-force, dictionary attack, hashing demo, or experiment runner routes/pages.

## Local-only / academic-only scope

These remain local CLI/academic features and are not part of public web deployment:

- `python main.py --demo`
- `python main.py --crack "..."`
- `python main.py --brute "..."`
- `python experiments/run_experiments.py`

## Privacy and safety boundary

- Passwords are analyzed transiently per request.
- Password values are not written to files/databases by the web app.
- No password analytics or storage is used in the frontend.
- No third-party services are called with password data.
- Cracking demos are local educational tooling and not publicly deployed.

## Project structure

```text
password-strength-analyzer/
├── app.py                     # FastAPI entrypoint for web/API
├── public/
│   ├── index.html             # Web UI
│   ├── style.css              # UI styling
│   └── app.js                 # UI behavior, calls /api/analyze
├── main.py                    # Existing CLI entrypoint
├── src/
│   ├── analyzer.py            # Core scoring logic (reused by API + CLI)
│   ├── dictionary_checker.py  # Word/common-password checks
│   ├── dictionary_attack.py   # Local-only educational demo
│   ├── brute_force.py         # Local-only educational demo
│   └── ...
├── data/
│   ├── common_passwords.txt
│   └── wordlist.txt
├── requirements.txt
└── vercel.json
```

## Local development

### 1) Install dependencies

```bash
pip install -r requirements.txt
```

### 2) Run the web app locally

```bash
uvicorn app:app --reload
```

### 3) Open in browser

`http://127.0.0.1:8000`

## API contract

### Health

- **GET** `/api/health`
- Example response:

```json
{ "ok": true, "service": "password-strength-analyzer" }
```

### Analyze

- **POST** `/api/analyze`
- Request body:

```json
{ "password": "MyP@ssw0rd!" }
```

- Response shape:

```json
{
  "score": 84,
  "label": "Very Strong",
  "reasons": ["..."],
  "suggestions": ["..."],
  "details": { "length_score": 22.5 }
}
```

Validation rules:

- missing/invalid/empty password: HTTP 400
- maximum password length: 256 chars

## CLI compatibility

Existing CLI flow is kept:

```bash
python main.py
python main.py --analyze "MyP@ss1!"
python main.py --demo
python main.py --crack "password"
python main.py --brute "abc"
```

## Vercel deployment

### Deploy steps

1. Push this repository to GitHub.
2. In Vercel, click **New Project** and import the repo.
3. Keep project root as repository root.
4. Deploy (the included `vercel.json` routes `/api/*` to `app.py` and serves `public/`).

After deploy:

- Web UI: `/`
- Health: `/api/health`
- Analyzer endpoint: `/api/analyze`

## Notes on file-path reliability

Wordlist/common-password loading uses `pathlib` paths resolved from module location (`src/dictionary_checker.py`), so it works in local CLI and serverless/runtime environments regardless of current working directory.
