import re
import os
import joblib
from detection.link.link_inspector import inspect_link
MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'models', 'sms_model.pkl')
_model = None
def _get_model():
    global _model
    if _model is None:
        if os.path.exists(MODEL_PATH):
            _model = joblib.load(MODEL_PATH)
        else:
            raise FileNotFoundError("SMS model not found. Run: python models/train_models.py")
    return _model

URL_PATTERN = re.compile(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+|[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?',re.IGNORECASE)
OBVIOUS_SPAM_TRIGGERS = [
    'lottery', 'winner', 'won cash', 'cash prize', 'claim prize', 'free iphone',
    'claim now', 'free money', '100% bonus', 'kbc lottery', '500% returns',
    'yono account will be blocked', 'sim card will be blocked', 'unpaid taxes arrest'
]
def extract_urls(text: str) -> list:
    return list(set(URL_PATTERN.findall(text)))
def analyze_sms(text: str, inspect_links: bool = True) -> dict:
    model = _get_model()
    text_lower = text.lower()
    # ML Prediction
    prediction = model.predict([text])[0]
    try:
        proba = model.predict_proba([text])[0]
        classes = list(model.classes_)
        spam_prob = float(proba[classes.index('spam')]) if 'spam' in classes else 0.5
        safe_prob = float(proba[classes.index('ham')]) if 'ham' in classes else 0.5
    except Exception:
        spam_prob = 0.85 if prediction == 'spam' else 0.15
        safe_prob = 1.0 - spam_prob

    # Extract URLs from SMS
    urls = extract_urls(text)
    link_results = []
    if inspect_links and urls:
        for url in urls[:3]:  # Limit to 3 links per SMS
            li = inspect_link(url)
            link_results.append(li)

    # Link safety status
    has_links = len(link_results) > 0
    all_links_safe = has_links and all(l.get('verdict') == 'SAFE' for l in link_results)
    any_link_dangerous = any(l.get('verdict') == 'DANGEROUS' for l in link_results)
    any_link_suspicious = any(l.get('verdict') == 'SUSPICIOUS' for l in link_results)
    max_link_risk = max((l.get('risk_score', 0) for l in link_results), default=0)

    if any_link_dangerous:
        composite_risk = max(80, max_link_risk)
        prediction = 'spam'
        spam_prob = max(spam_prob, 0.90)
        safe_prob = 1.0 - spam_prob
        verdict = 'SPAM'
    else:
        base_risk = int(spam_prob * 60)
        composite_risk = min(base_risk + int(max_link_risk * 0.4), 100)

        if composite_risk >= 65 or prediction == 'spam':
            verdict = 'SPAM'
        elif composite_risk >= 35 or any_link_suspicious:
            verdict = 'SUSPICIOUS'
        else:
            verdict = 'LEGITIMATE'

    display_prediction = 'SAFE' if prediction.lower() in ['ham', 'safe', 'legitimate'] and verdict != 'SPAM' else 'SPAM'
    confidence_val = spam_prob if verdict == 'SPAM' else safe_prob
    return {
        'verdict': verdict,
        'confidence': round(confidence_val, 4),
        'risk_score': composite_risk,
        'ml_prediction': display_prediction,
        'spam_probability': round(spam_prob, 4),
        'safe_probability': round(safe_prob, 4),
        'extracted_urls': urls,
        'url_count': len(urls),
        'link_inspections': link_results,
        'analysis_notes': _build_sms_notes(text, verdict, urls, link_results)
    }

def _build_sms_notes(text: str, verdict: str, urls: list, links: list) -> list:
    notes = []
    text_lower = text.lower()
    spam_triggers = ['win', 'prize', 'lottery', 'claim now', 'urgent', 'cash prize',
                     'congratulations', 'selected', 'suspended', 'free iphone']
    found = [t for t in spam_triggers if t in text_lower]
    if found:
        notes.append(f'Spam keywords detected: {", ".join(found[:4])}')
    if urls:
        notes.append(f'{len(urls)} embedded URL(s) extracted and inspected')
    for l in links:
        if l.get('verdict') == 'SAFE':
            final_host = l.get('final_url', l.get('url', ''))
            notes.append(f'Link verified safe: {final_host[:50]} (SSL secure)')
        elif l.get('verdict') == 'DANGEROUS':
            notes.append(f'Dangerous link detected: {l.get("url")}')
        elif l.get('verdict') == 'SUSPICIOUS':
            notes.append(f'Link requires caution: {l.get("url")}')
    if verdict == 'LEGITIMATE' and not notes:
        notes.append('Message content appears safe and authentic based on model classification')
    return notes