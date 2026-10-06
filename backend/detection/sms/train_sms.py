import os
import json
import pandas as pd
import joblib
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, 
    precision_score, 
    recall_score, 
    f1_score, 
    confusion_matrix
)

DATA_PATH = os.path.join(os.path.dirname(__file__), 'data', 'sms_dataset.csv')
MODEL_OUT = os.path.join(os.path.dirname(__file__), '..', '..', 'models', 'sms_model.pkl')
METRICS_OUT = os.path.join(os.path.dirname(__file__), '..', '..', 'models', 'sms_metrics.json')


def train():
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"SMS dataset not found: {DATA_PATH}")

    print("[sms] Loading dataset...")
    df = pd.read_csv(DATA_PATH, encoding='utf-8')
    texts, labels = df['text'].tolist(), df['label'].tolist()

    # Split dataset first to get sizes (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42
    )

    print("[sms] Training Naive Bayes pipeline...")
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(ngram_range=(1, 2), max_features=10000,sublinear_tf=True, stop_words='english')),
        ('clf', MultinomialNB(alpha=0.1))
    ])

    pipeline.fit(X_train, y_train)
    print("[sms] Evaluating model performance...")
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test).tolist() 

    # Calculate standard metrics
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, average='weighted', zero_division=0))
    rec = float(recall_score(y_test, y_pred, average='weighted', zero_division=0))
    f1 = float(f1_score(y_test, y_pred, average='weighted', zero_division=0))
    cm = confusion_matrix(y_test, y_pred).tolist()

    # Calculate Average Confidence across all test predictions
    test_confidences = [max(prob) * 100 for prob in y_prob]
    avg_confidence = float(sum(test_confidences) / len(test_confidences))

    total_size = len(df)
    train_size = len(X_train)
    test_size = len(X_test)

    # Print clean summary report
    print(f"\n--- Dataset Statistics ---")
    print(f"Total Dataset Size : {total_size}")
    print(f"Train Dataset Size : {train_size}")
    print(f"Test Dataset Size  : {test_size}")
    
    print(f"\n--- Model Performance ---")
    print(f"Accuracy           : {acc:.4f}")
    print(f"Precision          : {prec:.4f}")
    print(f"Recall             : {rec:.4f}")
    print(f"F1 Score           : {f1:.4f}")
    print(f"Average Confidence : {avg_confidence:.2f}%")
    print(f"Confusion Matrix   :\n{cm}")

    # Package all metrics and confidence scores for future graphing / reports
    metrics_data = {
        "total_size": total_size,
        "train_size": train_size,
        "test_size": test_size,
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1_score": f1,
        "average_confidence": avg_confidence,
        "confusion_matrix": cm,
        "y_true_test": y_test,
        "y_pred_test": y_pred.tolist(),
        "y_probabilities": y_prob,
        "test_confidences": test_confidences
    }

    # Save the trained model pipeline
    os.makedirs(os.path.dirname(MODEL_OUT), exist_ok=True)
    joblib.dump(pipeline, MODEL_OUT)
    print(f"\n[sms] Model successfully saved -> {MODEL_OUT}")

    # Save metrics JSON file for charting / visualizations later
    with open(METRICS_OUT, 'w', encoding='utf-8') as f:
        json.dump(metrics_data, f, indent=4)
    print(f"[sms] Metrics successfully saved -> {METRICS_OUT}")
    
    return pipeline


if __name__ == '__main__':
    train()