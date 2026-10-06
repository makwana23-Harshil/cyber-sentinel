import os
import pandas as pd
import joblib
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, 
    precision_score, 
    recall_score, 
    f1_score, 
    confusion_matrix
)

DATA_PATH = os.path.join(os.path.dirname(__file__), 'data', 'email_dataset.csv')
MODEL_OUT = os.path.join(os.path.dirname(__file__), '..', '..', 'models', 'email_body_model.pkl')


def train():
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"Email dataset not found: {DATA_PATH}")

    print("[email] Loading dataset with low_memory=False...")
    df = pd.read_csv(DATA_PATH, encoding='utf-8', low_memory=False)
    
    required_columns = ['sender', 'subject', 'body', 'urls', 'label']
    for col in required_columns:
        if col not in df.columns:
            raise KeyError(f"Missing expected column '{col}' in dataset. Found columns: {df.columns.tolist()}")

    df['label'] = pd.to_numeric(df['label'], errors='coerce')
    
    initial_len = len(df)
    df = df.dropna(subset=['label', 'body'])
    df['label'] = df['label'].astype(int) 

    dropped_count = initial_len - len(df)
    if dropped_count > 0:
        print(f"[email] Cleaned dataset: Dropped {dropped_count} rows with malformed or missing labels/bodies.")

    df['sender'] = df['sender'].fillna('')
    df['subject'] = df['subject'].fillna('')
    df['body'] = df['body'].fillna('')
    df['urls'] = df['urls'].fillna(0).astype(str)

    print("[email] Processing and combining text features...")
    texts = (
        "Sender: " + df['sender'] + " " +
        "Subject: " + df['subject'] + " " +
        "Body: " + df['body'] + " " +
        "URL Count: " + df['urls']
    ).tolist()
    
    labels = df['label'].tolist()

    # Split dataset into training (80%) and testing (20%) sets
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42
    )

    # Pipeline: TF-IDF Vectorizer + Random Forest Classifier
    print("[email] Training Random Forest model pipeline...")
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(ngram_range=(1, 2), max_features=15000,sublinear_tf=True, stop_words='english')),
        ('clf', RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1))
    ])

    pipeline.fit(X_train, y_train)
    
    print("[email] Evaluating model performance...")
    y_pred = pipeline.predict(X_test)

    # Calculate metrics and dataset sizes
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average='weighted', zero_division=0)
    rec = recall_score(y_test, y_pred, average='weighted', zero_division=0)
    f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    total_size = len(df)
    train_size = len(X_train)
    test_size = len(X_test)

    # Print summary report
    print(f"\n--- Dataset Statistics ---")
    print(f"Total Dataset Size : {total_size}")
    print(f"Train Dataset Size : {train_size}")
    print(f"Test Dataset Size  : {test_size}")
    
    print(f"\n--- Model Performance ---")
    print(f"Accuracy           : {acc:.2%}")
    print(f"Precision          : {prec:.4f}")
    print(f"Recall             : {rec:.4f}")
    print(f"F1 Score           : {f1:.4f}")
    print(f"Confusion Matrix   :\n{cm}")

    # Save the trained model
    os.makedirs(os.path.dirname(MODEL_OUT), exist_ok=True)
    joblib.dump(pipeline, MODEL_OUT)
    print(f"\n[email] Model successfully saved -> {MODEL_OUT}")
    
    return pipeline


if __name__ == '__main__':
    train()