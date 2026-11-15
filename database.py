"""SQLite setup + helpers (plain sqlite3). Seeds on first run."""
import sqlite3, os, time
from seed_data import PAYEES

DB_PATH = os.environ.get("RUKO_DB", os.path.join(os.path.dirname(__file__), "ruko.db"))

def conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c

def init_db(reset=False):
    if reset and os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    c = conn()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS payees(upi_id TEXT PRIMARY KEY, registered_name TEXT,
        account_age_days INTEGER, report_count INTEGER, verified INTEGER);
    CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY AUTOINCREMENT, upi_id TEXT, reason TEXT, ts REAL);
    CREATE TABLE IF NOT EXISTS checks(check_id TEXT PRIMARY KEY, kind TEXT, payee_upi TEXT, amount REAL,
        risk_score INTEGER, risk_level TEXT, scam_type TEXT, decision TEXT, ts REAL);
    CREATE TABLE IF NOT EXISTS stats(key TEXT PRIMARY KEY, value REAL);
    """)
    if c.execute("SELECT COUNT(*) FROM payees").fetchone()[0] == 0:
        c.executemany("INSERT INTO payees VALUES(?,?,?,?,?)", PAYEES)
        c.execute("INSERT OR IGNORE INTO stats VALUES('money_saved',0)")
    c.commit(); c.close()

def get_payee(upi):
    c = conn(); r = c.execute("SELECT * FROM payees WHERE upi_id=?", (upi.strip().lower(),)).fetchone(); c.close()
    return dict(r) if r else None

def had_prior_check(upi):
    c = conn(); n = c.execute("SELECT COUNT(*) FROM checks WHERE payee_upi=? AND decision IN ('paid_anyway')", (upi,)).fetchone()[0]; c.close()
    return n > 0

def save_check(check_id, kind, payee_upi, amount, score, level, scam_type):
    c = conn()
    c.execute("INSERT INTO checks VALUES(?,?,?,?,?,?,?,?,?)",
              (check_id, kind, payee_upi, amount, score, level, scam_type, None, time.time()))
    c.commit(); c.close()

def get_check(check_id):
    c = conn(); r = c.execute("SELECT * FROM checks WHERE check_id=?", (check_id,)).fetchone(); c.close()
    return dict(r) if r else None

def set_decision(check_id, decision):
    """Returns True if found. Adds amount to money_saved when cancelled on MEDIUM/HIGH."""
    ch = get_check(check_id)
    if not ch: return False
    c = conn()
    already = ch["decision"] == "cancelled"
    c.execute("UPDATE checks SET decision=? WHERE check_id=?", (decision, check_id))
    if decision == "cancelled" and ch["risk_level"] in ("MEDIUM", "HIGH") and not already:
        c.execute("UPDATE stats SET value=value+? WHERE key='money_saved'", (ch["amount"] or 0,))
    c.commit(); c.close()
    return True

def add_report(upi, reason):
    c = conn()
    c.execute("INSERT INTO reports(upi_id,reason,ts) VALUES(?,?,?)", (upi, reason, time.time()))
    if c.execute("SELECT 1 FROM payees WHERE upi_id=?", (upi,)).fetchone():
        c.execute("UPDATE payees SET report_count=report_count+1 WHERE upi_id=?", (upi,))
    else:
        c.execute("INSERT INTO payees VALUES(?,?,?,?,0)", (upi, None, None, 1))
    n = c.execute("SELECT report_count FROM payees WHERE upi_id=?", (upi,)).fetchone()[0]
    c.commit(); c.close()
    return n

def stats():
    c = conn()
    total = c.execute("SELECT COUNT(*) FROM checks").fetchone()[0]
    high = c.execute("SELECT COUNT(*) FROM checks WHERE risk_level='HIGH'").fetchone()[0]
    saved = c.execute("SELECT value FROM stats WHERE key='money_saved'").fetchone()[0]
    by = {r[0]: r[1] for r in c.execute(
        "SELECT scam_type, COUNT(*) FROM checks WHERE risk_level!='LOW' AND scam_type IS NOT NULL GROUP BY scam_type")}
    c.close()
    return {"total_checked": total, "high_risk_caught": high, "money_saved": saved, "by_scam_type": by}
