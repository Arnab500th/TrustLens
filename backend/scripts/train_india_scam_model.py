# backend/scripts/train_india_scam_model.py
# Downloads and trains a local ML model on anmolshrivastav/scam-ham-india dataset.
import csv
import io
import os
import urllib.request
import joblib

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
CSV_PATH = os.path.join(DATA_DIR, "scam_hum_india.csv")
MODEL_PATH = os.path.join(DATA_DIR, "scam_india_model.joblib")
HF_URL = "https://huggingface.co/datasets/anmolshrivastav/scam-ham-india/resolve/main/scam_hum_india.csv"


def download_dataset():
    if os.path.exists(CSV_PATH) and os.path.getsize(CSV_PATH) > 1000:
        print(f"[Dataset] Using cached CSV at {CSV_PATH}")
        return CSV_PATH

    print(f"[Dataset] Downloading from Hugging Face: {HF_URL}")
    req = urllib.request.Request(HF_URL, headers={"User-Agent": "Mozilla/5.0 TrustLens"})
    with urllib.request.urlopen(req) as resp, open(CSV_PATH, "wb") as out:
        out.write(resp.read())
    print(f"[Dataset] Downloaded {os.path.getsize(CSV_PATH):,} bytes.")
    return CSV_PATH


def load_data(csv_path):
    texts, labels = [], []
    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        for row in reader:
            if len(row) >= 2:
                text, label = row[0].strip(), row[1].strip().lower()
                if text and label in ("scam", "ham", "spam"):
                    # normalize label: 1 for scam/spam, 0 for ham
                    texts.append(text)
                    labels.append(1 if label in ("scam", "spam") else 0)
    print(f"[Data] Loaded {len(texts)} samples (Scam: {sum(labels)}, Ham: {len(labels) - sum(labels)})")
    return texts, labels


def train_and_save():
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score

    csv_path = download_dataset()
    texts, labels = load_data(csv_path)

    X_train, X_test, y_train, y_test = train_test_split(texts, labels, test_size=0.2, random_state=42, stratify=labels)

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=8000, sublinear_tf=True)),
        ("clf", LogisticRegression(class_weight="balanced", max_iter=500, C=1.5))
    ])

    print("[Training] Fitting model on Indian SMS dataset...")
    pipeline.fit(X_train, y_train)

    preds = pipeline.predict(X_test)
    acc = accuracy_score(y_test, preds)
    print(f"[Evaluation] Accuracy: {acc * 100:.2f}%")
    print(classification_report(y_test, preds, target_names=["Ham", "Scam"]))

    # Save model
    joblib.dump(pipeline, MODEL_PATH)
    print(f"[Model Saved] -> {MODEL_PATH} ({os.path.getsize(MODEL_PATH):,} bytes)")

    # Sample tests
    samples = [
        "Dear customer your SBI netbanking blocked today update your KYC at http://sbi-kyc.top",
        "Hi, are we meeting for coffee today at 5pm?",
        "Congratulations you have won Rs 50,000 lottery claim now at bit.ly/prize"
    ]
    print("\n--- Model Predictions on Test Samples ---")
    for s in samples:
        prob = pipeline.predict_proba([s])[0][1]
        verdict = "SCAM" if prob >= 0.5 else "HAM"
        print(f"[{verdict} ({prob*100:.1f}%)] \"{s}\"")


if __name__ == "__main__":
    train_and_save()

