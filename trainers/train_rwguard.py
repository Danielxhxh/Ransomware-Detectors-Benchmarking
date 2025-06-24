import numpy as np
from sklearn import metrics
from sklearn.model_selection import train_test_split
from models import MODEL_REGISTRY
import csv
import os
from scripts.utils.load_config import config, BASE_DIR

# MODEL_NAME = 'random_forest'  

TIME_WINDOW = config['time_window'] 
BENIGN_FEATURES_PATH = BASE_DIR / 'datasets' / 'features' / 'RWGuard' 
RANSOMWARE_FEATURES_PATH = BASE_DIR / 'datasets' / 'features' / 'RWGuard'

MODEL_PATH = BASE_DIR / 'saved_models'

def load_csv_features(path, feature_cols=[0,1,2,3,4,5,6,7], label_col=8):
    X, y = [], []
    print(f"Loading features from {path}")
    with open(path) as f:
        reader = csv.reader(f)
        for i, row in enumerate(reader, 1):
            try:
                features = [float(row[i]) for i in feature_cols]
                label = row[label_col]
                X.append(features)
                y.append(label)
            except Exception as e:
                print(f"Row {i} in {path} is malformed: {e}")
    return np.array(X), np.array(y)

def train_model(model_name: str):
    print("Starting RWGuard training script")

    # ──────────────── Load and merge datasets ────────────────
    benign_x, benign_y = load_csv_features(f'{BENIGN_FEATURES_PATH}/benign_rwguard_features_{TIME_WINDOW}sec.csv')
    ransomware_x, ransomware_y = load_csv_features(f'{RANSOMWARE_FEATURES_PATH}/ransomware_rwguard_features_{TIME_WINDOW}sec.csv')

    X = np.concatenate((benign_x, ransomware_x))
    y = np.concatenate((benign_y, ransomware_y))
    print(f"Loaded {len(X)} total samples ({len(benign_x)} benign, {len(ransomware_x)} ransomware)")

    # ──────────────── Split data ────────────────
    train_x, test_x, train_y, test_y = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    print(f"Training set size: {len(train_x)}, Testing set size: {len(test_x)}")

    # ──────────────── Train model ────────────────
    model = MODEL_REGISTRY[model_name]()
    print(f"Training '{model_name}' model...")
    model.train(train_x, train_y)
    print("Model training completed")

    # ──────────────── Save model ────────────────

    model_path = f"{MODEL_PATH}/rwguard_{model_name}_{TIME_WINDOW}sec.joblib"
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    model.save(model_path)
    print(f"Model saved to {model_path}")

    # ──────────────── Evaluate model ────────────────
    print("Evaluating model on test set...")
    predictions = model.predict(test_x)
    accuracy = metrics.accuracy_score(test_y, predictions)
    print(f"Test Accuracy: {accuracy:.4f}")
