import os
import joblib
import numpy as np
from detection.link.link_inspector import inspect_link
from detection.url.features import extract_url_features, build_url_notes

# detection/url/url_detector.py -> backend/models/url_model.pkl
MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'models', 'url_model.pkl')
_model = None

def _get_model():
    global _model
    if _model is None:
        if os.path.exists(MODEL_PATH):
            _model = joblib.load(MODEL_PATH)
        else:
            raise FileNotFoundError("URL model not found. Run: python models/train_models.py")
    return _model

def analyze_url(url: str, do_inspect: bool = True) -> dict:
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url_for_model = 'http://' + url
    else:
        url_for_model = url

    # ML prediction on lexical features
    model = _get_model()
    features = np.array(extract_url_features(url_for_model)).reshape(1, -1)
    ml_prediction = model.predict(features)[0]  # 1=legitimate, 0=phishing
    try:
        ml_proba = model.predict_proba(features)[0]
        phish_prob = float(ml_proba[0])
        legit_prob = float(ml_proba[1])
    except Exception:
        phish_prob = 0.85 if ml_prediction == 0 else 0.15
        legit_prob = 1 - phish_prob

    ml_risk = int(phish_prob * 60)

    # Deep link inspection (DNS, HTTP status, Typosquatting, Content, SSL, LLM)
    inspection = {}
    if do_inspect:
        inspection = inspect_link(url_for_model)

    inspection_risk = inspection.get('risk_score', 0) if inspection else 0
    inspection_verdict = inspection.get('verdict', 'UNKNOWN') if inspection else 'UNKNOWN'

    # Determine final composite verdict
    # Real-world verification must take priority over purely lexical ML
    if inspection_verdict in ('FAKE', 'NON-EXISTENT'):
        verdict = inspection_verdict
        composite_risk = max(75, inspection_risk)
        phish_prob = 0.90
        legit_prob = 0.10
    elif inspection_verdict == 'PHISHING':
        verdict = 'PHISHING'
        composite_risk = max(85, inspection_risk)
        phish_prob = 0.95
        legit_prob = 0.05
    elif inspection_verdict == 'DANGEROUS':
        verdict = 'DANGEROUS'
        composite_risk = max(75, inspection_risk)
        phish_prob = 0.90
        legit_prob = 0.10
    elif inspection_verdict == 'SAFE':
        # If the site exists, has valid SSL and clean content
        verdict = 'SAFE'
        composite_risk = min(inspection_risk, 15)
        legit_prob = 0.98
        phish_prob = 0.02
    else:
        composite_risk = min(int(ml_risk * 0.4 + inspection_risk * 0.6), 100)
        if composite_risk >= 65:
            verdict = 'PHISHING'
        elif composite_risk >= 35:
            verdict = 'SUSPICIOUS'
        else:
            verdict = 'SAFE'

    # Synchronize ML prediction label with unified verdict to eliminate contradictions
    if verdict in ('FAKE', 'NON-EXISTENT'):
        ml_pred_label = verdict
        phish_prob = max(phish_prob, 0.95)
        legit_prob = 1.0 - phish_prob
    elif verdict in ('PHISHING', 'DANGEROUS'):
        ml_pred_label = 'PHISHING'
        phish_prob = max(phish_prob, 0.95)
        legit_prob = 1.0 - phish_prob
    elif verdict == 'SAFE':
        ml_pred_label = 'SAFE'
        legit_prob = max(legit_prob, 0.98)
        phish_prob = 1.0 - legit_prob
    else:
        ml_pred_label = 'SUSPICIOUS'

    feature_notes = build_url_notes(url_for_model, features[0])

    return {
        'verdict': verdict,
        'confidence': round(phish_prob if verdict in ('PHISHING', 'FAKE', 'DANGEROUS', 'NON-EXISTENT') else legit_prob, 4),
        'risk_score': composite_risk,
        'ml_prediction': ml_pred_label,
        'phishing_probability': round(phish_prob, 4),
        'legitimate_probability': round(legit_prob, 4),
        'url_features': feature_notes,
        'deep_inspection': inspection if inspection else None
    }

