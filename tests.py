import os, tempfile
os.environ["RUKO_DB"] = os.path.join(tempfile.mkdtemp(), "t.db")
from fastapi.testclient import TestClient
from main import app
from seed_data import SCENARIOS

def run(i):
    with TestClient(app) as c:
        s = next(x for x in SCENARIOS if x["id"] == i)
        if s["mode"] == "message":
            return c.post("/api/analyze-message", json={"text": s["message"]}).json()
        return c.post("/api/analyze-payment", json=s["payment"]).json()

def test_health():
    with TestClient(app) as c: assert c.get("/api/health").json() == {"status": "ok"}
def test_s1_high(): assert run(1)["risk_level"] == "HIGH"
def test_s2_high(): assert run(2)["risk_level"] == "HIGH"
def test_s3_med_or_high(): assert run(3)["risk_level"] in ("MEDIUM", "HIGH")
def test_s4_message_high():
    r = run(4); assert r["risk_level"] == "HIGH" and r["scam_type"] == "ELECTRICITY_BILL_THREAT"
def test_s5_low(): assert run(5)["risk_level"] == "LOW"
def test_reasons_bilingual():
    for r in run(1)["reasons"]: assert r["text_en"] and r["text_hi"]
def test_decision_and_stats():
    with TestClient(app) as c:
        r = c.post("/api/analyze-payment", json=SCENARIOS[0]["payment"]).json()
        assert c.post("/api/decision", json={"check_id": r["check_id"], "decision": "cancelled"}).json()["ok"]
        assert c.get("/api/stats").json()["money_saved"] >= 4999
        assert "Alert sent" in c.post("/api/notify-contact", json={"check_id": r["check_id"]}).json()["message"]
def test_validation(): 
    with TestClient(app) as c: assert c.post("/api/analyze-payment", json={"amount": -1}).status_code == 422
