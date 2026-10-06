import os
import sys
import pandas as pd
import joblib
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV

DATA_PATH = os.path.join(os.path.dirname(__file__), 'data', 'email_dataset.csv')
MODEL_OUT = os.path.join(os.path.dirname(__file__), '..', '..', 'models', 'email_body_model.pkl')


TEST_SAMPLE = [
    "Sender: security-alert@example.net "
    "Subject: URGENT: Your Account Requires Immediate Verification "
    "Body: Dear User, We detected unusual activity on your account. Your account "
    "will be temporarily suspended today unless you complete the security verification "
    "immediately. Click the link below to verify your account: "
    "http://secure-account-verification.example.net/login You must provide the following "
    "information: Email Address Password Account Verification Code Failure to complete "
    "verification within 30 minutes may result in permanent account suspension. "
    "Verify Your Account: http://secure-account-verification.example.net/login "
    "Security Department Account Protection Team URL Count: 1"
]


def train():
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"Email dataset not found: {DATA_PATH}")

    print("=" * 70)
    print("  CyberSentinel — Email Model Training (Option B: Voting Ensemble)")
    print("=" * 70)

    print("\n[1/5] Loading email dataset...")
    df = pd.read_csv(DATA_PATH, encoding='utf-8', low_memory=False)

    required_columns = ['sender', 'subject', 'body', 'urls', 'label']
    for col in required_columns:
        if col not in df.columns:
            raise KeyError(f"Missing expected column '{col}' in dataset.")

    df['label'] = pd.to_numeric(df['label'], errors='coerce')
    initial_len = len(df)
    df = df.dropna(subset=['label', 'body'])
    df['label'] = df['label'].astype(int)

    dropped = initial_len - len(df)
    if dropped > 0:
        print(f"      Cleaned {dropped:,} invalid rows.")

    df['sender'] = df['sender'].fillna('')
    df['subject'] = df['subject'].fillna('')
    df['body'] = df['body'].fillna('')
    df['urls'] = df['urls'].fillna(0).astype(str)

    print("[2/5] Preparing feature representations...")
    texts = (
        "Sender: " + df['sender'] + " " +
        "Subject: " + df['subject'] + " " +
        "Body: " + df['body'] + " " +
        "URL Count: " + df['urls']
    ).tolist()

    labels = df['label'].tolist()
    total_samples = len(texts)
    phish_count = sum(labels)
    safe_count = total_samples - phish_count

    print(f"      Total Samples : {total_samples:,}")
    print(f"      Phishing (1)  : {phish_count:,}")
    print(f"      Safe (0)      : {safe_count:,}")

    # Split dataset: 80% train, 20% test
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )

    print("\n[3/5] Configuring Option B: Tri-Model Soft Voting Ensemble...")
    print("      • Sub-Model 1: Random Forest Classifier (100 Trees)")
    print("      • Sub-Model 2: Linear Support Vector Machine (LinearSVC, Calibrated)")
    print("      • Sub-Model 3: Logistic Regression (L2 Balanced)")

    ensemble = VotingClassifier(
        estimators=[
            ('rf', RandomForestClassifier(n_estimators=100, max_depth=30, random_state=42, n_jobs=-1)),
            ('svm', CalibratedClassifierCV(LinearSVC(C=1.0, class_weight='balanced', random_state=42), cv=3)),
            ('lr', LogisticRegression(C=2.0, class_weight='balanced', max_iter=1000, random_state=42))
        ],
        voting='soft'
    )

    # Full Pipeline: TF-IDF -> Soft Voting Ensemble
    pipeline = Pipeline([('tfidf', TfidfVectorizer(ngram_range=(1, 2),max_features=15000,sublinear_tf=True,stop_words='english')),
        ('clf', ensemble)
    ])

    print("\n[4/5] Training pipeline on dataset...")
    pipeline.fit(X_train, y_train)

    print("\n[5/5] Evaluating performance on 20% holdout test set...")
    y_pred = pipeline.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average='weighted', zero_division=0)
    rec = recall_score(y_test, y_pred, average='weighted', zero_division=0)
    f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    print("\n" + "-" * 45)
    print("       MODEL EVALUATION METRICS")
    print("-" * 45)
    print(f"  Accuracy           : {acc:.2%}")
    print(f"  Precision          : {prec:.4f}")
    print(f"  Recall             : {rec:.4f}")
    print(f"  F1 Score           : {f1:.4f}")
    print(f"\n  Confusion Matrix   :\n{cm}")
    print("-" * 45)

    # Test on the sample phishing email
    sample_pred = pipeline.predict(TEST_SAMPLE)[0]
    sample_proba = pipeline.predict_proba(TEST_SAMPLE)[0]
    phish_prob = round(sample_proba[1] * 100, 2)
    safe_prob = round(sample_proba[0] * 100, 2)

    print("\n--- Phishing Test Sample Verification ---")
    print(f"  Prediction         : {'PHISHING' if sample_pred == 1 else 'SAFE'}")
    print(f"  Phishing Conf      : {phish_prob}%")
    print(f"  Safe Conf          : {safe_prob}%")

    # Save trained model artifact
    MODEL_OUT_ABS = os.path.abspath(MODEL_OUT)
    os.makedirs(os.path.dirname(MODEL_OUT_ABS), exist_ok=True)
    joblib.dump(pipeline, MODEL_OUT_ABS)
    print(f"\n[+] Model successfully saved to:\n    {MODEL_OUT_ABS}")
    print("=" * 70 + "\n")

    return pipeline


if __name__ == '__main__':
    train()
