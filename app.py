"""
FastAPI web entrypoint for password strength analysis.
"""

from pathlib import Path

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse

from src.analyzer import analyze

MAX_PASSWORD_LENGTH = 256
BASE_DIR = Path(__file__).resolve().parent
PUBLIC_DIR = BASE_DIR / "public"

app = FastAPI(title="password-strength-analyzer")


@app.middleware("http")
async def add_response_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


@app.get("/api/health")
def health() -> dict:
    return {"ok": True, "service": "password-strength-analyzer"}


@app.post("/api/analyze")
def analyze_password(payload: dict = Body(...)) -> dict:
    password = payload.get("password")
    if not isinstance(password, str):
        raise HTTPException(status_code=400, detail="`password` must be a string.")
    if password == "":
        raise HTTPException(status_code=400, detail="`password` must not be empty.")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"`password` must be at most {MAX_PASSWORD_LENGTH} characters.",
        )
    return analyze(password)


@app.get("/")
def index() -> FileResponse:
    return FileResponse(PUBLIC_DIR / "index.html")


@app.get("/style.css")
def style() -> FileResponse:
    return FileResponse(PUBLIC_DIR / "style.css")


@app.get("/app.js")
def script() -> FileResponse:
    return FileResponse(PUBLIC_DIR / "app.js")
