import re
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from passlib.hash import sha256_crypt

app = FastAPI(title="SAP CDC Custom Hash Endpoint")

SALT_PATTERN = re.compile(r"^[A-Za-z0-9./]+$")

class HashResponse(BaseModel):
    hashedPassword: str

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/hash", response_model=HashResponse)
def hash_password(
    password: str = Query(..., min_length=1),
    pwHashSalt: str = Query(..., min_length=1, max_length=16),
    pwHashRounds: int = Query(..., ge=1000, le=999999999)
):
    if not SALT_PATTERN.match(pwHashSalt):
        raise HTTPException(
            status_code=400,
            detail="pwHashSalt must contain only [A-Za-z0-9./]"
        )

    try:
        mcf_value = sha256_crypt.using(
            rounds=pwHashRounds,
            salt=pwHashSalt
        ).hash(password)

        return HashResponse(hashedPassword=mcf_value)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))