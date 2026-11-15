"""Message scam checker: TF-IDF + Logistic Regression (trained at startup) + regex flags."""
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from seed_data import MESSAGES

# (regex, reason_en, reason_hi)
FLAGS = [
    (r"\b(urgent(ly)?|immediately|at once|turant|abhi)\b", "Urgency word - scammers rush you.", "जल्दबाज़ी का दबाव - ठग आपको सोचने का समय नहीं देते।"),
    (r"https?://\S+|\b(bit\.ly|tinyurl\.com)\S*", "Suspicious or shortened link.", "संदिग्ध या छोटा लिंक।"),
    (r"click here|click karke|is link par", "Asks you to click a link.", "लिंक पर क्लिक करने को कहा जा रहा है।"),
    (r"\b(otp|upi pin|pin|cvv)\b", "Asks for OTP / PIN. Nobody genuine ever asks for it.", "OTP/PIN माँगा जा रहा है। असली कंपनी कभी नहीं माँगती।"),
    (r"kyc (is )?(pending|expire\w*|update)|kyc pending|pan kyc", "'KYC pending' is a classic scam line.", "'KYC pending' ठगों की पुरानी चाल है।"),
    (r"(account|card|sim)( is| will be)? (blocked|suspended|band)|account blocked|will be blocked", "Threat of account being blocked.", "अकाउंट बंद होने की धमकी।"),
    (r"(send|pay|bhej\w*)\s+(rs\.?|₹)\s*\d[\d,]*.{0,40}(receive|verify|claim|update)|processing fee|registration fee", "Asks you to pay money first to get something.", "कुछ पाने के लिए पहले पैसे भेजने को कहा जा रहा है।"),
    (r"lottery|prize|lucky draw|jackpot|inaam|winner|you won", "Lottery / prize claim.", "लॉटरी/इनाम का झाँसा।"),
    (r"(electricity|bijli|power)\b.{0,40}(disconnect|cut|kat|bill)|disconnected", "Electricity disconnection threat.", "बिजली कटने की धमकी।"),
    (r"\brefund\b|cashback|collect request|approve the", "Refund / cashback bait.", "रिफंड/कैशबैक का लालच।"),
    (r"\badvance\b|security fee|registration|job offer|work from home", "Advance-fee / job bait.", "एडवांस फीस / नौकरी का झाँसा।"),
    (r"\b(customs|courier|parcel)\b", "Courier / customs fee trick.", "कूरियर/कस्टम फीस की ठगी।"),
]

TYPE_RULES = [  # priority order
    ("ELECTRICITY_BILL_THREAT", r"electricity|bijli|power (will be )?disconnect"),
    ("FAKE_KYC", r"kyc"),
    ("LOTTERY_PRIZE", r"lottery|prize|lucky draw|inaam|jackpot|you won"),
    ("FAKE_REFUND", r"refund|cashback|paisa wapas"),
    ("COLLECT_REQUEST", r"collect request|approve|accept the request|scan this qr"),
    ("JOB_OR_ADVANCE_FEE", r"\badvance\b|registration fee|security fee|job|processing fee|naukri"),
    ("PHISHING_LINK", r"https?://|bit\.ly|tinyurl|click here"),
]

ADVICE = {
    "en": "Do NOT click links, share OTP/PIN or send money. Call the official number printed on your bank card or bill.",
    "hi": "लिंक पर क्लिक न करें, OTP/PIN न बताएँ और पैसे न भेजें। अपने बैंक कार्ड या बिल पर छपे असली नंबर पर फ़ोन करें।",
}
SAFE_ADVICE = {"en": "This looks like a normal message. Stay careful with unknown links.",
               "hi": "यह सामान्य संदेश लगता है। अनजान लिंक से फिर भी सावधान रहें।"}

_model = None
def train():
    global _model
    X = [t for t, _ in MESSAGES]; y = [l for _, l in MESSAGES]
    _model = make_pipeline(TfidfVectorizer(ngram_range=(1, 2), lowercase=True), LogisticRegression(C=10, max_iter=1000))
    _model.fit(X, y)

def analyze_message(text):
    if _model is None: train()
    low = text.lower()
    flags, seen = [], set()
    for rx, en, hi in FLAGS:
        for m in re.finditer(rx, low):
            phrase = text[m.start():m.end()].strip()
            if phrase and phrase.lower() not in seen:
                seen.add(phrase.lower())
                flags.append({"phrase": phrase, "reason_en": en, "reason_hi": hi})
    p = float(_model.predict_proba([text])[0][1])
    score = int(min(100, round(p * 60 + 14 * len(flags))))
    if not flags and p < 0.5: score = min(score, 25)
    level = "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"
    stype = "LIKELY_SAFE"
    if level != "LOW":
        stype = "PHISHING_LINK"
        for t, rx in TYPE_RULES:
            if re.search(rx, low): stype = t; break
    adv = SAFE_ADVICE if level == "LOW" else ADVICE
    return {"risk_score": score, "risk_level": level, "scam_type": stype, "flags": flags,
            "advice_en": adv["en"], "advice_hi": adv["hi"]}
