import re
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from passlib.hash import sha256_crypt

app = FastAPI(title="MCF SHA256-Crypt Generator")

SALT_PATTERN = re.compile(r"^[A-Za-z0-9./]+$")

class HashRequest(BaseModel):
    password: str = Field(..., min_length=1)
    salt: str = Field(..., min_length=1, max_length=16)
    rounds: int = Field(..., ge=1000, le=999999999)

class HashResponse(BaseModel):
    mcf: str

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/hash", response_model=HashResponse)
def hash_password(req: HashRequest):

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