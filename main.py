import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

from database import db, create_document

app = FastAPI(title="HireLens Backend", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class SendOtpRequest(BaseModel):
    identifier: str
    via: Literal["email", "phone"]


class VerifyOtpRequest(BaseModel):
    identifier: str
    otp: str


def is_valid_phone(value: str) -> bool:
    # Simple E.164-ish check: starts with + and 8-15 digits, or 10-15 digits
    return bool(re.fullmatch(r"(\+?\d{10,15})", value.strip()))


@app.get("/")
def read_root():
    return {"message": "HireLens FastAPI Backend is running"}


@app.get("/ping")
def ping():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}


@app.post("/send-otp")
def send_otp(body: SendOtpRequest):
    identifier = body.identifier.strip()

    if body.via == "email":
        try:
            # Validate email strictly
            _ = EmailStr(identifier)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid email address")
    else:
        if not is_valid_phone(identifier):
            raise HTTPException(status_code=400, detail="Invalid phone number")

    # Generate a 6-digit numeric OTP
    code = f"{uuid.uuid4().int % 1000000:06d}"
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

    # Persist OTP record
    try:
        create_document(
            "otp",
            {
                "identifier": identifier.lower() if body.via == "email" else identifier,
                "via": body.via,
                "code": code,
                "consumed": False,
                "expires_at": expires_at,
            },
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

    # In a real system, send via email/SMS provider. For now, log to server output.
    print(f"[OTP] Sending {code} to {identifier} via {body.via}")

    # Include debug_code so testers can complete the flow without real email/SMS
    return {"status": "sent", "debug_code": code}


@app.post("/verify-otp")
def verify_otp(body: VerifyOtpRequest):
    identifier = body.identifier.strip()

    # Normalize email to lowercase for matching consistency
    q_identifier = identifier.lower()

    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    # Find the latest matching OTP document
    doc = (
        db["otp"]
        .find_one(
            {
                "$or": [
                    {"identifier": q_identifier},
                    {"identifier": identifier},
                ],
                "code": body.otp,
            }
        )
    )

    if not doc:
        raise HTTPException(status_code=400, detail="Invalid code")

    if doc.get("consumed"):
        raise HTTPException(status_code=400, detail="Code already used")

    expires_at = doc.get("expires_at")
    if isinstance(expires_at, str):
        try:
            expires_at = datetime.fromisoformat(expires_at)
        except Exception:
            pass
    if not expires_at or datetime.now(timezone.utc) > expires_at:
        raise HTTPException(status_code=400, detail="Code expired")

    # Mark as consumed
    db["otp"].update_one({"_id": doc["_id"]}, {"$set": {"consumed": True, "updated_at": datetime.now(timezone.utc)}})

    # Generate a simple session token (not a JWT)
    token = uuid.uuid4().hex

    return {"status": "verified", "token": token}


@app.get("/api/hello")
def hello():
    return {"message": "Hello from the backend API!"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": [],
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, "name") else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"

    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    import os as _os

    response["database_url"] = "✅ Set" if _os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if _os.getenv("DATABASE_NAME") else "❌ Not Set"

    return response


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
