import numpy as np
from sklearn import metrics
from sklearn.model_selection import train_test_split
from models import MODEL_REGISTRY
import logging
import csv
import os

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%H:%M'
)

MODEL_NAME = 'random_forest'  # Change this to the model you want to use

def load_csv_features(path, feature_cols=[0,1,2,3,4,5,6,7], label_col=8):
    X, y = [], []
    logging.info(f"Loading features from {path}")
    with open(path) as f:
        reader = csv.reader(f)
        for i, row in enumerate(reader, 1):
            try:
                features = [float(row[i]) for i in feature_cols]
                label = row[label_col]
                X.append(features)
                y.append(label)
            except Exception as e:
                logging.error(f"Row {i} in {path} is malformed: {e}")
    return np.array(X), np.array(y)

def main():
    logging.info("Starting RWGuard training script")

    # ──────────────── Load and merge datasets ────────────────
    benign_x, benign_y = load_csv_features('datasets/features/RWGuard/benign_rwguard_features_3sec.csv')
    ransomware_x, ransomware_y = load_csv_features('datasets/features/RWGuard/ransomware_rwguard_features_3sec.csv')

    X = np.concatenate((benign_x, ransomware_x))
    y = np.concatenate((benign_y, ransomware_y))
    logging.info(f"Loaded {len(X)} total samples ({len(benign_x)} benign, {len(ransomware_x)} ransomware)")

    # ──────────────── Split data ────────────────
    train_x, test_x, train_y, test_y = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    logging.info(f"Training set size: {len(train_x)}, Testing set size: {len(test_x)}")

    # ──────────────── Train model ────────────────
    model = MODEL_REGISTRY[MODEL_NAME]()
    logging.info(f"Training '{MODEL_NAME}' model...")
    model.train(train_x, train_y)
    logging.info("Model training completed")

    # ──────────────── Save model ────────────────
    model_path = f"saved_models/rwguard_{MODEL_NAME}.joblib"
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    model.save(model_path)
    logging.info(f"Model saved to {model_path}")

    # ──────────────── Evaluate model ────────────────
    logging.info("Evaluating model on test set...")
    predictions = model.predict(test_x)
    accuracy = metrics.accuracy_score(test_y, predictions)
    logging.info(f"Test Accuracy: {accuracy:.4f}")

if __name__ == "__main__":
    main()
