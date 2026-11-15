"""RUKO backend - FastAPI. Run: uvicorn main:app --reload"""
import uuid
from typing import Literal
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field
import database as db, risk_engine, message_model
from seed_data import USER, SCENARIOS

app = FastAPI(title="RUKO - Pause. Verify. Pay.")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
                   allow_methods=["*"], allow_headers=["*"])

@app.on_event("startup")
def startup():
    db.init_db()
    message_model.train()

@app.exception_handler(RequestValidationError)
async def _422(request, exc):
    return JSONResponse(status_code=422, content={"detail": "Invalid input", "errors": [
        {"field": ".".join(str(x) for x in e["loc"][1:]), "msg": e["msg"]} for e in exc.errors()]})

class PaymentIn(BaseModel):
    payee_upi: str = Field(min_length=3)
    payee_name_entered: str = ""
    amount: float = Field(gt=0)
    note: str = ""
    txn_type: Literal["pay", "collect"] = "pay"
    hour_of_day: int = Field(ge=0, le=23, default=12)

class MessageIn(BaseModel):
    text: str = Field(min_length=1)

class ReportIn(BaseModel):
    upi_id: str = Field(min_length=3)
    reason: str = ""

class DecisionIn(BaseModel):
    check_id: str
    decision: Literal["cancelled", "paid_anyway", "called_contact"]

class CheckIn(BaseModel):
    check_id: str

@app.get("/api/health")
def health(): return {"status": "ok"}

@app.post("/api/analyze-payment")
def analyze_payment(body: PaymentIn):
    upi = body.payee_upi.strip().lower()
    payee = db.get_payee(upi)
    r = risk_engine.analyze(payee, body.model_dump() | {"payee_upi": upi}, USER, first_time=not db.had_prior_check(upi))
    cid = str(uuid.uuid4())
    db.save_check(cid, "payment", upi, body.amount, r["risk_score"], r["risk_level"], r.pop("scam_type"))
    return {"check_id": cid, **r}

@app.post("/api/analyze-message")
def analyze_message(body: MessageIn):
    r = message_model.analyze_message(body.text)
    db.save_check(str(uuid.uuid4()), "message", None, 0, r["risk_score"], r["risk_level"], r["scam_type"])
    return r

@app.get("/api/payee/{upi_id}")
def payee(upi_id: str):
    p = db.get_payee(upi_id)
    if not p:
        return {"upi_id": upi_id, "registered_name": None, "account_age_days": None, "report_count": 0, "verified_merchant": False}
    return {"upi_id": p["upi_id"], "registered_name": p["registered_name"], "account_age_days": p["account_age_days"],
            "report_count": p["report_count"], "verified_merchant": bool(p["verified"])}

@app.post("/api/report-id")
def report_id(body: ReportIn):
    return {"ok": True, "report_count": db.add_report(body.upi_id.strip().lower(), body.reason)}

@app.get("/api/scenarios")
def scenarios(): return SCENARIOS

@app.post("/api/decision")
def decision(body: DecisionIn):
    if not db.set_decision(body.check_id, body.decision):
        raise HTTPException(404, "check_id not found")
    return {"ok": True}

@app.post("/api/notify-contact")
def notify(body: CheckIn):
    ch = db.get_check(body.check_id)
    if not ch: raise HTTPException(404, "check_id not found")
    amt = f"Rs {ch['amount']:,.0f}" if ch["amount"] else "money"
    return {"ok": True, "message": f"Alert sent to {USER['trusted_contact']}: {USER['name']} is about to pay {amt} to a risky ID ({ch['payee_upi'] or 'unknown'})"}

@app.get("/api/stats")
def stats(): return db.stats()
