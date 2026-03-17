import re
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from passlib.hash import sha256_crypt

app = FastAPI(title="SAP CDC Custom Hash Endpoint")

SALT_PATTERN = re.compile(r"^[A-Za-z0-9./+]+$")

class HashResponse(BaseModel):
    hashedPassword: str

def add_base64_padding(value: str) -> str:
    remainder = len(value) % 4
    if remainder == 0:
        return value
    return value + ("=" * (4 - remainder))

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/hash", response_model=HashResponse)
def hash_password(
    password: str = Query(..., min_length=1),
    pwHashSalt: str = Query(..., min_length=1, max_length=16),
    pwHashRounds: int = Query(..., ge=1000, le=999999999)
):
    try:
        if not SALT_PATTERN.match(pwHashSalt):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid salt charset: [{pwHashSalt}]"
            )

        # Workaround CDC: parfois . arrive transformé en +
        normalized_salt = pwHashSalt.replace("+", ".")

        mcf_value = sha256_crypt.using(
            rounds=pwHashRounds,
            salt=normalized_salt
        ).hash(password)

        # Format: $5$rounds=7000$salt$HASH
        hash_only = mcf_value.split("$")[-1]

        # Adaptation vers format base64-style attendu par CDC
        base64_style_hash = hash_only.replace(".", "+")
        base64_style_hash = add_base64_padding(base64_style_hash)

        return HashResponse(hashedPassword=base64_style_hash)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))