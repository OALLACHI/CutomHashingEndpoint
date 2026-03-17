import os
import re
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, Field
from passlib.hash import sha256_crypt

app = FastAPI(title="MCF SHA256-Crypt Generator")

API_KEY = os.getenv("API_KEY", "")
SALT_PATTERN = re.compile(r"^[A-Za-z0-9./]+$")

class HashRequest(BaseModel):
    password: str = Field(..., min_length=1)
    salt: str = Field(..., min_length=1, max_length=16)
    rounds: int = Field(..., ge=1000, le=999999999)

class HashResponse(BaseModel):
    mcf: str

def check_api_key(x_api_key: str | None):
    if not API_KEY:
        raise HTTPException(status_code=500, detail="Server API key not configured")
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

@app.on_event("startup")
async def startup():
    if not API_KEY:
        raise RuntimeError("API_KEY environment variable must be configured")

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/hash", response_model=HashResponse)
def hash_password(req: HashRequest, x_api_key: str | None = Header(default=None)):
    check_api_key(x_api_key)

    if not SALT_PATTERN.match(req.salt):
        raise HTTPException(
            status_code=400,
            detail="Salt must contain only [A-Za-z0-9./]"
        )

    try:
        mcf_value = sha256_crypt.using(
            rounds=req.rounds,
            salt=req.salt
        ).hash(req.password)

        return HashResponse(mcf=mcf_value)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))