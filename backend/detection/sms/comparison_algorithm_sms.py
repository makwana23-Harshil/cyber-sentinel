"""
=============================================================================
CyberSentinel — SMS Spam & Threat Detection Algorithm Benchmark
File: comparison_algorithm_sms.py
Location: D:\\mojor project show in exhibition\\CyberSentinel-Pro\\backend\\detection\\sms\\
=============================================================================
This script compares 6 algorithms on the SMS dataset:
  1. Multinomial Naive Bayes (MNB) — Excellent baseline for SMS/text classification
  2. Bernoulli Naive Bayes (BNB)   — Good for binary word-presence features
  3. Logistic Regression          — Strong TF-IDF text classifier with calibrated probabilities
  4. Linear SVM (LinearSVC)       — High-dimensional maximum-margin hyperplane
  5. Random Forest                — Non-linear tree-based ensemble
  6. Gradient Boosting            — Sequential error-correcting decision trees

Metrics evaluated:
  - Accuracy (%)
  - Precision (%)
  - Recall (%)
  - F1-Score (%)
  - Training Time (seconds)
  - Prediction on a real spam SMS test sample!

Output:
  - Local Matplotlib GUI Window with side-by-side grouped bar charts
  - High-res image: algorithm_comparison_chart_sms.png
=============================================================================
"""

import os
import sys
import time
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# 6 Algorithms
from sklearn.naive_bayes import MultinomialNB, BernoulliNB
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(CURRENT_DIR, 'data', 'sms_dataset.csv')
CHART_PNG = os.path.join(CURRENT_DIR, 'algorithm_comparison_chart_sms.png')

# Real spam test message to test all 6 models
TEST_SAMPLE_SMS = (
    "URGENT: Your bank account has been suspended due to suspicious activity. "
    "Verify your identity immediately to prevent closure: http://secure-bank-verify.xyz/login "
    "or call 0800-432-111 within 15 minutes."
)


def load_sms_data():
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"SMS dataset not found at: {DATA_PATH}")

    print(f"\n[1/3] Loading SMS dataset from: {DATA_PATH} ...")
    df = pd.read_csv(DATA_PATH, encoding='utf-8', low_memory=False)

    if 'text' not in df.columns or 'label' not in df.columns:
        raise KeyError(f"Expected columns 'text' and 'label' in SMS dataset. Found: {df.columns.tolist()}")

    df = df.dropna(subset=['text', 'label'])
    texts = df['text'].astype(str).tolist()

    # Map labels: 'spam' -> 1, 'ham' -> 0 (or numeric)
    raw_labels = df['label'].astype(str).str.lower().str.strip()
    labels = [1 if ('spam' in l or l == '1') else 0 for l in raw_labels]

    spam_count = sum(labels)
    ham_count = len(labels) - spam_count
    print(f"      Total SMS Messages : {len(texts):,} (Spam: {spam_count:,}, Ham: {ham_count:,})")

    return train_test_split(texts, labels, test_size=0.2, random_state=42, stratify=labels)


def get_models():
    """Defines the 6 algorithms requested for SMS comparison"""
    return {
        "1. Multinomial NB\n(Current MNB)": MultinomialNB(alpha=0.1),
        "2. Bernoulli NB\n(BNB)": BernoulliNB(alpha=0.1),
        "3. Logistic\nRegression": LogisticRegression(C=2.0, class_weight='balanced', max_iter=1000, random_state=42),
        "4. Linear SVM\n(LinearSVC)": CalibratedClassifierCV(
            LinearSVC(C=1.0, class_weight='balanced', random_state=42), cv=3
        ),
        "5. Random\nForest": RandomForestClassifier(n_estimators=100, max_depth=30, random_state=42, n_jobs=-1),
        "6. Gradient\nBoosting": GradientBoostingClassifier(n_estimators=100, learning_rate=0.1, max_depth=5, random_state=42)
    }


def evaluate_and_plot():
    X_train, X_test, y_train, y_test = load_sms_data()

    print("\n[2/3] Extracting TF-IDF features (1-2 n-grams, max 10,000 features)...")
    vectorizer = TfidfVectorizer(max_features=10000, ngram_range=(1, 2), sublinear_tf=True, stop_words='english')
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)
    sample_vec = vectorizer.transform([TEST_SAMPLE_SMS])

    models = get_models()
    results = []

    print("\n[3/3] Training and scoring all 6 algorithms...\n")
    print("=" * 115)
    print(f"{'Algorithm':<32} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'Time':<9} | {'Sample Test':<14}")
    print("=" * 115)

    for name, clf in models.items():
        clean_name = name.replace('\n', ' ')
        t0 = time.time()
        clf.fit(X_train_vec, y_train)
        train_time = round(time.time() - t0, 3)

        preds = clf.predict(X_test_vec)
        acc = round(accuracy_score(y_test, preds) * 100, 2)
        prec = round(precision_score(y_test, preds, zero_division=0) * 100, 2)
        rec = round(recall_score(y_test, preds, zero_division=0) * 100, 2)
        f1 = round(f1_score(y_test, preds, zero_division=0) * 100, 2)

        # Test on the sample spam message
        sample_pred = clf.predict(sample_vec)[0]
        try:
            sample_proba = clf.predict_proba(sample_vec)[0]
            spam_pct = round(sample_proba[1] * 100, 1)
            sample_label = f"SPAM ({spam_pct}%)" if sample_pred == 1 else f"HAM ({spam_pct}%)"
        except Exception:
            sample_label = "SPAM" if sample_pred == 1 else "HAM"

        results.append({
            "display_name": name,
            "clean_name": clean_name,
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "time": f"{train_time}s",
            "sample_pred": sample_label
        })

        print(f"{clean_name:<32} | {acc:>8.2f}% | {prec:>8.2f}% | {rec:>8.2f}% | {f1:>8.2f}% | {train_time:>7.3f}s | {sample_label:<14}")

    print("=" * 115)

    plot_matplotlib(results)


def plot_matplotlib(results):
    """Renders local grouped bar chart and table summary"""
    names = [r['display_name'] for r in results]
    accuracies = [r['accuracy'] for r in results]
    precisions = [r['precision'] for r in results]
    recalls = [r['recall'] for r in results]
    f1_scores = [r['f1_score'] for r in results]

    plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(17, 7.5), gridspec_kw={'width_ratios': [3.5, 1.3]})

    # --- SUBPLOT 1: Grouped Bar Chart ---
    x = np.arange(len(names))
    width = 0.19

    rects1 = ax1.bar(x - 1.5 * width, accuracies, width, label='Accuracy', color='#2563eb', edgecolor='black', linewidth=0.5)
    rects2 = ax1.bar(x - 0.5 * width, precisions, width, label='Precision', color='#059669', edgecolor='black', linewidth=0.5)
    rects3 = ax1.bar(x + 0.5 * width, recalls, width, label='Recall', color='#d97706', edgecolor='black', linewidth=0.5)
    rects4 = ax1.bar(x + 1.5 * width, f1_scores, width, label='F1-Score', color='#7c3aed', edgecolor='black', linewidth=0.5)

    ax1.set_title('SMS Spam & Threat Detection — Algorithm Benchmark Comparison', fontsize=14, fontweight='bold', pad=15)
    ax1.set_ylabel('Score (%)', fontsize=11, fontweight='bold')
    ax1.set_xticks(x)
    ax1.set_xticklabels(names, fontsize=9, fontweight='bold')
    ax1.set_ylim(85, 103)
    ax1.legend(loc='lower right', frameon=True, framealpha=0.9, fontsize=10)

    # Add numeric labels on bars
    for rects in [rects1, rects2, rects3, rects4]:
        for rect in rects:
            h = rect.get_height()
            ax1.annotate(f'{h:.1f}%',
                         xy=(rect.get_x() + rect.get_width() / 2, h),
                         xytext=(0, 3), textcoords="offset points",
                         ha='center', va='bottom', fontsize=7.2, rotation=90)

    # --- SUBPLOT 2: Table Summary ---
    ax2.axis('off')
    table_data = []
    for r in results:
        table_data.append([
            r['clean_name'].split('(')[0].strip(),
            f"{r['f1_score']:.1f}%",
            r['time'],
            r['sample_pred']
        ])

    table = ax2.table(
        cellText=table_data,
        colLabels=['Algorithm', 'F1', 'Time', 'Sample Test'],
        loc='center',
        cellLoc='center'
    )
    table.auto_set_font_size(False)
    table.set_fontsize(8.2)
    table.scale(1.15, 2.1)

    # Header styling
    for k in range(4):
        table[(0, k)].set_facecolor('#0f172a')
        table[(0, k)].set_text_props(color='white', fontweight='bold')

    # Color-code sample result: Green if caught as SPAM, Red if missed as HAM
    for row_idx, r in enumerate(results, start=1):
        cell = table[(row_idx, 3)]
        if "SPAM" in r['sample_pred']:
            cell.set_facecolor('#dcfce7')
            cell.set_text_props(color='#166534', fontweight='bold')
        else:
            cell.set_facecolor('#fee2e2')
            cell.set_text_props(color='#991b1b', fontweight='bold')

    ax2.set_title('Training Speed &\nSample Test Result', fontsize=11, fontweight='bold', pad=15)

    plt.tight_layout()
    plt.savefig(CHART_PNG, dpi=300, bbox_inches='tight')
    print(f"\n[+] Matplotlib Chart saved to image: {CHART_PNG}")
    print("[+] Opening local Matplotlib GUI window...")

    try:
        plt.show()
    except Exception as e:
        print(f"    (GUI window note: {e})")


if __name__ == '__main__':
    evaluate_and_plot()
