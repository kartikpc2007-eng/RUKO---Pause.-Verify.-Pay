"""Rule-based payment risk scoring. One function per rule -> (points, reason) or None.
Scores are summed, floored at 0 and capped at 100."""
import re
from difflib import SequenceMatcher

SCAM_WORDS = ["refund", "kyc", "lottery", "prize", "cashback", "reward", "urgent", "blocked",
              "advance", "courier", "customs", "electricity disconnect"]

def _r(code, sev, en, hi):
    return {"code": code, "severity": sev, "text_en": en, "text_hi": hi}

def rule_new_account(p, req, user):
    if p and p["account_age_days"] is not None and p["account_age_days"] < 7:
        d = p["account_age_days"]
        return 25, _r("NEW_ACCOUNT", "high", f"This UPI ID is only {d} day(s) old. Scammers use brand-new IDs.",
                      f"यह UPI ID सिर्फ {d} दिन पुरानी है। ठग अक्सर नई ID बनाते हैं।")

def rule_reported(p, req, user):
    n = p["report_count"] if p else 0
    if n >= 3:
        return 40, _r("REPORTED_ID", "high", f"Other users reported this ID {n} times as a scam.",
                      f"दूसरे लोगों ने इस ID को {n} बार ठगी के लिए रिपोर्ट किया है।")
    if n >= 1:
        return 20, _r("REPORTED_ID", "medium", f"This ID has been reported {n} time(s).",
                      f"इस ID की {n} बार शिकायत हो चुकी है।")

def rule_name_mismatch(p, req, user):
    if p and p["registered_name"] and req["payee_name_entered"].strip():
        sim = SequenceMatcher(None, req["payee_name_entered"].lower().strip(), p["registered_name"].lower()).ratio()
        if sim < 0.6:
            return 25, _r("NAME_MISMATCH", "high",
                          f"You expected '{req['payee_name_entered']}' but this ID is registered to '{p['registered_name']}'.",
                          f"आपने '{req['payee_name_entered']}' सोचा था, लेकिन यह ID '{p['registered_name']}' के नाम पर है।")

def rule_collect_trap(p, req, user):
    if req["txn_type"] == "collect" and not (p and p["verified"]):
        return 30, _r("COLLECT_REQUEST_TRAP", "high",
                      "A collect request means you SEND money. You never need to approve anything to RECEIVE money.",
                      "कलेक्ट रिक्वेस्ट का मतलब है आप पैसे भेज रहे हैं। पैसे पाने के लिए कुछ भी अप्रूव नहीं करना पड़ता।")

def rule_unusual_amount(p, req, user):
    pts, a = 0, req["amount"]
    if a > 5 * user["avg_txn"]: pts += 15
    if a > user["max_txn"]: pts += 10
    if pts:
        return pts, _r("UNUSUAL_AMOUNT", "medium",
                       f"Rs {a:,.0f} is much more than your usual payment (about Rs {user['avg_txn']:,.0f}).",
                       f"₹{a:,.0f} आपके सामान्य भुगतान (लगभग ₹{user['avg_txn']:,.0f}) से बहुत ज़्यादा है।")

def rule_scam_keywords(p, req, user):
    note = req["note"].lower()
    found = [w for w in SCAM_WORDS if re.search(r"\b" + re.escape(w), note)]
    if found:
        return 20, _r("SCAM_KEYWORDS", "high", f"The note has scam-style words: {', '.join(found)}.",
                      f"नोट में ठगी वाले शब्द हैं: {', '.join(found)}।")

def rule_first_time(p, req, user, first_time=True):
    if first_time:
        return 10, _r("FIRST_TIME_PAYEE", "low", "You have never paid this ID before.",
                      "आपने इस ID को पहले कभी पैसे नहीं भेजे।")

def rule_odd_hour(p, req, user):
    if 0 <= req["hour_of_day"] < 5:
        return 5, _r("ODD_HOUR", "low", "Late-night payments are a common scam pattern.",
                     "रात के समय के भुगतान में ठगी ज़्यादा होती है।")

def rule_verified(p, req, user):
    if p and p["verified"]:
        return -30, _r("VERIFIED_MERCHANT", "low", "This is a verified merchant.", "यह एक सत्यापित (वेरिफाइड) दुकानदार है।")

def scam_type_for(req, reasons):
    note = req["note"].lower()
    if "kyc" in note: return "FAKE_KYC"
    if "refund" in note: return "FAKE_REFUND"
    if "advance" in note: return "JOB_OR_ADVANCE_FEE"
    if any(w in note for w in ("lottery", "prize")): return "LOTTERY_PRIZE"
    if any(r["code"] == "COLLECT_REQUEST_TRAP" for r in reasons): return "COLLECT_REQUEST"
    return "SUSPICIOUS_PAYEE"

def analyze(payee, req, user, first_time=True):
    results = [rule_new_account(payee, req, user), rule_reported(payee, req, user),
               rule_name_mismatch(payee, req, user), rule_collect_trap(payee, req, user),
               rule_unusual_amount(payee, req, user), rule_scam_keywords(payee, req, user),
               rule_first_time(payee, req, user, first_time), rule_odd_hour(payee, req, user),
               rule_verified(payee, req, user)]
    results = [r for r in results if r]
    score = max(0, min(100, sum(p for p, _ in results)))
    reasons = [r for _, r in results]
    if score >= 60: level, action, pause = "HIGH", "PAUSE_AND_VERIFY", 10
    elif score >= 30: level, action, pause = "MEDIUM", "CONFIRM", 5
    else: level, action, pause = "LOW", "PROCEED", 0
    return {"risk_score": score, "risk_level": level, "reasons": reasons,
            "recommended_action": action, "cooling_off_seconds": pause,
            "money_at_risk": req["amount"] if level != "LOW" else 0,
            "scam_type": scam_type_for(req, reasons)}
