"""
=============================================================================
CyberSentinel — URL Malicious Link Detection Algorithm Benchmark
File: comparison_algorithm_url.py
Location: D:\\mojor project show in exhibition\\CyberSentinel-Pro\\backend\\detection\\url\\
Dataset: url_final.csv
=============================================================================
This script compares the requested algorithms on url_final.csv using the
system's 15 handcrafted lexical & structural URL features:
  1. Current (Gradient Boosting) — Sequential boosting of weak decision trees
  2. Random Forest              — Ensemble of decision trees with bagging
  3. Support Vector Machine     — Linear hyperplane with probability calibration
  4. Logistic Regression        — L2-regularized linear weighting
  5. Decision Tree              — Single decision tree baseline

Metrics evaluated:
  - Accuracy (%)
  - Precision (%)
  - Recall (%)
  - F1-Score (%)
  - Training Time (seconds)
  - Prediction on real sample phishing URL!

Output:
  - Local Matplotlib GUI Window with side-by-side grouped bar charts
  - High-res image: algorithm_comparison_chart_url.png
=============================================================================
"""

import os
import sys
import time
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# Ensure features.py can be imported
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from features import extract_url_features

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# Algorithms requested by user
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier

DATA_PATH = os.path.join(CURRENT_DIR, 'data', 'url_final.csv')
CHART_PNG = os.path.join(CURRENT_DIR, 'algorithm_comparison_chart_url.png')

# Real sample phishing URL for live prediction test
TEST_SAMPLE_URL = "http://sbi-kyc-verification.top/secure-login/account-verify"


def load_url_data(sample_limit=15000):
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"Dataset not found at: {DATA_PATH}")

    print(f"\n[1/3] Loading dataset from: {DATA_PATH} ...")
    df = pd.read_csv(DATA_PATH, encoding='utf-8', low_memory=False)

    if 'url' not in df.columns or 'label' not in df.columns:
        raise KeyError(f"Expected 'url' and 'label' columns. Found: {df.columns.tolist()}")

    df = df.dropna(subset=['url', 'label'])
    df['label'] = pd.to_numeric(df['label'], errors='coerce')
    df = df.dropna(subset=['label'])
    df['label'] = df['label'].astype(int)

    if len(df) > sample_limit:
        print(f"      Dataset has {len(df):,} rows. Sampling {sample_limit:,} rows for rapid feature extraction...")
        df = df.sample(n=sample_limit, random_state=42)

    urls = df['url'].astype(str).tolist()
    labels = df['label'].tolist()

    print(f"[2/3] Extracting 15 lexical features from {len(urls):,} URLs via features.py ...")
    t0 = time.time()
    feature_list = []
    valid_labels = []

    for i, (u, l) in enumerate(zip(urls, labels)):
        try:
            feats = extract_url_features(u)
            feature_list.append(feats)
            valid_labels.append(l)
        except Exception:
            continue

    extract_time = round(time.time() - t0, 2)
    print(f"      Finished feature extraction in {extract_time}s.")

    X = np.array(feature_list)
    y = np.array(valid_labels)

    phish_count = int(np.sum(y == 1))
    safe_count = int(np.sum(y == 0))
    print(f"      Total Samples: {len(y):,} (Phishing: {phish_count:,}, Safe/Legitimate: {safe_count:,})")

    return train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)


def get_models():
    """Defines the algorithms requested by user"""
    return {
        "1. Gradient Boosting\n(Current Model)": GradientBoostingClassifier(
            n_estimators=100, learning_rate=0.1, max_depth=5, random_state=42
        ),
        "2. Random Forest": RandomForestClassifier(
            n_estimators=100, max_depth=15, random_state=42, n_jobs=-1
        ),
        "3. Support Vector\nMachine (SVM)": CalibratedClassifierCV(
            LinearSVC(C=1.0, class_weight='balanced', max_iter=2000, random_state=42), cv=3
        ),
        "4. Logistic\nRegression": LogisticRegression(
            C=2.0, class_weight='balanced', max_iter=1000, random_state=42
        ),
        "5. Decision Tree": DecisionTreeClassifier(
            max_depth=12, random_state=42
        )
    }


def evaluate_and_plot():
    X_train, X_test, y_train, y_test = load_url_data()

    # Scale numeric features for SVM and Logistic Regression stability
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Prepare test sample feature vector
    sample_feat = np.array(extract_url_features(TEST_SAMPLE_URL)).reshape(1, -1)
    sample_feat_scaled = scaler.transform(sample_feat)

    models = get_models()
    results = []

    print("\n[3/3] Training and scoring each algorithm...\n")
    print("=" * 115)
    print(f"{'Algorithm':<32} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'Time':<9} | {'Sample Test':<14}")
    print("=" * 115)

    for name, clf in models.items():
        clean_name = name.replace('\n', ' ')
        
        # Use scaled features for linear models (SVM, Logistic Regression), unscaled for trees
        is_linear = ("SVM" in name or "Logistic" in name)
        train_X = X_train_scaled if is_linear else X_train
        test_X = X_test_scaled if is_linear else X_test
        eval_sample = sample_feat_scaled if is_linear else sample_feat

        t0 = time.time()
        clf.fit(train_X, y_train)
        train_time = round(time.time() - t0, 3)

        preds = clf.predict(test_X)
        acc = round(accuracy_score(y_test, preds) * 100, 2)
        prec = round(precision_score(y_test, preds, zero_division=0) * 100, 2)
        rec = round(recall_score(y_test, preds, zero_division=0) * 100, 2)
        f1 = round(f1_score(y_test, preds, zero_division=0) * 100, 2)

        # Test on the sample phishing URL
        sample_pred = clf.predict(eval_sample)[0]
        try:
            sample_proba = clf.predict_proba(eval_sample)[0]
            phish_pct = round(sample_proba[1] * 100, 1)
            sample_label = f"PHISH ({phish_pct}%)" if sample_pred == 1 else f"SAFE ({phish_pct}%)"
        except Exception:
            sample_label = "PHISHING" if sample_pred == 1 else "SAFE"

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
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 7), gridspec_kw={'width_ratios': [3.3, 1.3]})

    # --- SUBPLOT 1: Grouped Bar Chart ---
    x = np.arange(len(names))
    width = 0.19

    rects1 = ax1.bar(x - 1.5 * width, accuracies, width, label='Accuracy', color='#2563eb', edgecolor='black', linewidth=0.5)
    rects2 = ax1.bar(x - 0.5 * width, precisions, width, label='Precision', color='#059669', edgecolor='black', linewidth=0.5)
    rects3 = ax1.bar(x + 0.5 * width, recalls, width, label='Recall', color='#d97706', edgecolor='black', linewidth=0.5)
    rects4 = ax1.bar(x + 1.5 * width, f1_scores, width, label='F1-Score', color='#7c3aed', edgecolor='black', linewidth=0.5)

    ax1.set_title('URL Phishing Detection — Algorithm Benchmark (url_final.csv)', fontsize=14, fontweight='bold', pad=15)
    ax1.set_ylabel('Score (%)', fontsize=11, fontweight='bold')
    ax1.set_xticks(x)
    ax1.set_xticklabels(names, fontsize=9.5, fontweight='bold')
    ax1.set_ylim(80, 103)
    ax1.legend(loc='lower right', frameon=True, framealpha=0.9, fontsize=10)

    # Add numeric labels on bars
    for rects in [rects1, rects2, rects3, rects4]:
        for rect in rects:
            h = rect.get_height()
            ax1.annotate(f'{h:.1f}%',
                         xy=(rect.get_x() + rect.get_width() / 2, h),
                         xytext=(0, 3), textcoords="offset points",
                         ha='center', va='bottom', fontsize=7.5, rotation=90)

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
    table.set_fontsize(8.5)
    table.scale(1.15, 2.1)

    # Header styling
    for k in range(4):
        table[(0, k)].set_facecolor('#0f172a')
        table[(0, k)].set_text_props(color='white', fontweight='bold')

    # Color-code sample result: Green if caught as PHISH, Red if missed as SAFE
    for row_idx, r in enumerate(results, start=1):
        cell = table[(row_idx, 3)]
        if "PHISH" in r['sample_pred']:
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
