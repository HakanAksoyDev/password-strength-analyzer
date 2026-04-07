"""
FastAPI web entrypoint for password strength analysis.
"""

from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, StrictStr

from src.analyzer import analyze

MAX_PASSWORD_LENGTH = 256
BASE_DIR = Path(__file__).resolve().parent
PUBLIC_DIR = BASE_DIR / "public"

app = FastAPI(title="password-strength-analyzer")


class AnalyzeRequest(BaseModel):
    password: StrictStr
    model_config = ConfigDict(extra="forbid")


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


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    detail = "Invalid request body."
    for err in exc.errors():
        loc = err.get("loc", ())
        err_type = err.get("type", "")
        if "password" in loc and err_type == "missing":
            detail = "`password` is required."
            break
        if "password" in loc and err_type in {"string_type", "string_sub_type"}:
            detail = "`password` must be a string."
            break
    return JSONResponse(status_code=400, content={"detail": detail})


@app.get("/api/health")
def health() -> dict:
    return {"ok": True, "service": "password-strength-analyzer"}


@app.post("/api/analyze")
def analyze_password(payload: AnalyzeRequest) -> dict:
    password = payload.password
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
