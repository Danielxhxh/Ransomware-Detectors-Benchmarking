from collections import defaultdict
import numpy as np
from sklearn import metrics
from sklearn.model_selection import train_test_split
from models import MODEL_REGISTRY
import yaml
import os
import gzip
import sys
import csv
import joblib
from datetime import datetime
from pathlib import Path
from scripts.utils.load_config import config, BASE_DIR
from scripts.utils.calculate_hash import calculate_hash

TIME_WINDOW = config['RWGuard']['time_window'] 
LOGS_PATH = BASE_DIR / 'data' / 'ShieldFS-dataset' 
FEATURES_PATH = BASE_DIR / 'datasets' / 'RWGuard'
SAVED_MODELS_PATH = BASE_DIR / 'saved_models'
RESULTS_PATH = BASE_DIR / 'results' / 'RWGuard'
ATTACKS_PATH = BASE_DIR / 'ATTACKS'

REGULAR_IO = 'IRP'
FAST_IO = 'FIO'
ACTIONS = {
    'FILE_READ': ['IRP_MJ_READ'],
    'FILE_WRITE': ['IRP_MJ_WRITE'],
    'IRP_OPEN': ['IRP_MJ_CREATE'],
    'IRP_CLOSE': ['IRP_MJ_CLOSE']
}

SESSION_PID_MAP = {
    '480bd1ecb1b969e6677c1e11a30cd985e4244e5de04956e2dbb0e6b97c42027e.gz': '2616',
    '09c278fc0ae3a36170a71e65bba9f92da086fca941ba93051811bf16c6b67f64.gz': '2060',
    '0d6fb25cde440df0d2b6a676e86b23c47c298f60f8ec461805cc4cd77dd9f730.gz': '3680',
    'c80d611b38c6ea23cf9d564111a24f245f48df48a5341da896912054dd7d9529.gz': '3684'
}

class RWGuard:
    def __init__(self):
        self.time_window = TIME_WINDOW
        self.actions = ACTIONS
        self.session_pid_map = SESSION_PID_MAP

    @staticmethod
    def date_diff_in_seconds(dt2, dt1):
        return (dt2 - dt1).total_seconds()

    @staticmethod
    def rreplace(s, old, new):
        return (s[::-1].replace(old[::-1], new[::-1], 1))[::-1]

    @staticmethod
    def update_feature(features, current_time, pid, key, parsed_time):
        features[pid][key] += 1
        current_time[pid] = parsed_time

    @staticmethod
    def load_csv_features(path, feature_cols=[0,1,2,3,4,5,6,7], label_col=8):
        X, y = [], []
        print(f"    📂 Loading features from: {path}")
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
    
    def extract_ransomware_features(self ):
        logs_path = LOGS_PATH / "ransomware-irp-logs"
        output_file = FEATURES_PATH / f"ransomware_rwguard_features_{self.time_window}sec.csv"
        session_pid_map = self.session_pid_map
        for session_name in os.listdir(logs_path):
            session_path = logs_path / session_name
            if not session_path.is_file() or not session_name.endswith('.gz'):
                continue

            print(f"Processing ransomware session: {session_name}")
            features = defaultdict(lambda: {k: 0 for k in [
                'READ', 'WRITE', 'OPEN', 'CLOSE',
                'FAST_READ', 'FAST_WRITE', 'FAST_OPEN', 'FAST_CLOSE']})
            global_features = []
            previous_time = {}
            current_time = {}

            ransomware_pid = session_pid_map.get(session_name)
            print(f"Using ransomware PID: {ransomware_pid}")

            try:
                with gzip.open(session_path, 'rt', encoding='utf-8', errors='ignore') as fin:
                    next(fin)
                    next(fin)

                    for line_num, line in enumerate(fin, 3):
                        line = line.strip().split('\t')
                        if len(line) != 23:
                            continue

                        try:
                            major_op = line[7].strip()
                            operation_type = line[0].strip()
                            process_pid = line[4].split('.')[0].strip()
                            post_time = self.rreplace(line[3].strip(), ':', '.')
                            if process_pid != ransomware_pid:
                                continue

                            parsed_time = datetime.strptime(post_time, '%H:%M:%S.%f')
                        except Exception as e:
                            print(f"Parse error in {session_name} line {line_num}: {e}")
                            continue

                        previous_time.setdefault(process_pid, parsed_time)
                        current_time[process_pid] = parsed_time

                        if operation_type == REGULAR_IO:
                            for key, ops in self.actions.items():
                                if major_op in ops:
                                    self.update_feature(features, current_time, process_pid, key.split('_')[1], parsed_time)
                        elif operation_type == FAST_IO:
                            for key, ops in self.actions.items():
                                if major_op in ops:
                                    self.update_feature(features, current_time, process_pid, 'FAST_' + key.split('_')[1], parsed_time)

                        if self.date_diff_in_seconds(current_time[process_pid], previous_time[process_pid]) >= self.time_window:
                            counts = features[process_pid]
                            if any(counts.values()):
                                global_features.append(list(counts.values()) + ['M'])
                            previous_time[process_pid] = current_time[process_pid]
                            for k in counts:
                                counts[k] = 0

                with open(output_file, 'a', newline='') as f:
                    csv.writer(f).writerows(global_features)

                print(f"Finished session {session_name}")

            except Exception as e:
                print(f"Error in {session_name}: {e}")

    def extract_benign_features(self):
        output_file = FEATURES_PATH / f"benign_rwguard_features_{self.time_window}sec.csv"
        benign_logs_path = LOGS_PATH / "benign-irp-logs"

        for machine_name in os.listdir(benign_logs_path):
            machine_path = benign_logs_path / machine_name
            if not machine_path.is_dir():
                continue
            print(f"Processing machine: {machine_name}")

            for session_name in os.listdir(machine_path):
                session_folder_path = machine_path / session_name
                if not session_folder_path.is_dir():
                    continue

                print(f"Processing session: {session_name}")
                features = defaultdict(lambda: {'READ': 0, 'WRITE': 0, 'OPEN': 0, 'CLOSE': 0,
                                            'FAST_READ': 0, 'FAST_WRITE': 0,  'FAST_OPEN': 0, 'FAST_CLOSE': 0})
                global_features = []
                previous_time = {}
                current_time = {}

                for in_file in os.listdir(session_folder_path):
                    if not in_file.endswith('.gz'):
                        continue

                    try:
                        with gzip.open(session_folder_path / in_file, 'rt', encoding='utf-8', errors='ignore') as fin:
                            for line_num, line in enumerate(fin, 1):
                                line = line.strip().split('\t')
                                if len(line) != 23:
                                    continue

                                try:
                                    major_op = line[7].strip()
                                    operation_type = line[0].strip()
                                    process_pid = line[4].split('.')[0].strip()
                                    post_time = self.rreplace(line[3].strip(), ':', '.')
                                    parsed_time = datetime.strptime(post_time, '%H:%M:%S.%f')
                                except Exception as e:
                                    print(f"Parse error in {in_file} line {line_num}: {e}")
                                    continue

                                previous_time.setdefault(process_pid, parsed_time)
                                current_time[process_pid] = parsed_time

                                if operation_type == REGULAR_IO:
                                    for key, ops in self.actions.items():
                                        if major_op in ops:
                                            self.update_feature(features, current_time, process_pid, key.split('_')[1], parsed_time)
                                elif operation_type == FAST_IO:
                                    for key, ops in self.actions.items():
                                        if major_op in ops:
                                            self.update_feature(features, current_time, process_pid, 'FAST_' + key.split('_')[1], parsed_time)

                                if self.date_diff_in_seconds(current_time[process_pid], previous_time[process_pid]) >= self.time_window:
                                    counts = features[process_pid]
                                    if any(counts.values()):
                                        global_features.append(list(counts.values()) + ['N'])
                                    previous_time[process_pid] = current_time[process_pid]
                                    for k in counts:
                                        counts[k] = 0

                        if global_features:
                            with open(output_file, 'a', newline='') as f:
                                csv.writer(f).writerows(global_features)
                            global_features.clear()

                    except Exception as e:
                        print(f"Error reading {in_file}: {e}")
                print(f"Finished session {session_name}")

    def train_model(self, model_name):
        benign_features_path = FEATURES_PATH / f"benign_rwguard_features_{self.time_window}sec.csv"
        ransomware_features_path = FEATURES_PATH / f"ransomware_rwguard_features_{self.time_window}sec.csv"

        #  Load and merge datasets 
        benign_x, benign_y = self.load_csv_features(benign_features_path)
        ransomware_x, ransomware_y = self.load_csv_features(ransomware_features_path)

        X = np.concatenate((benign_x, ransomware_x))
        y = np.concatenate((benign_y, ransomware_y))
        print(f"    ⬆ Loaded {len(X)} total samples ({len(benign_x)} benign, {len(ransomware_x)} ransomware)\n")

        #  Split data 
        train_x, test_x, train_y, test_y = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
        print(f"    📊 Training set size: {len(train_x)}, Testing set size: {len(test_x)}")

        #  Train model 
        model_params = config["ShieldFS"].get(model_name, {})
        model_class = MODEL_REGISTRY[model_name]
        model = model_class(**model_params)
        
        print(f"    Training '{model_name}' model...")
        model.train(train_x, train_y)
        print(f"    ✅ Model training completed")

        #  Save model 
        model_path = SAVED_MODELS_PATH / f"{calculate_hash('RWGuard', model_name)}.pkl"
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        model.save(model_path)

    def evaluate(self, model_name, saved_model):
        # Path to results
        results_file = RESULTS_PATH / "evaluation_results.csv"
        
        # Paths to features
        benign_features_path = FEATURES_PATH / f"benign_rwguard_features_{self.time_window}sec.csv"
        ransomware_features_path = FEATURES_PATH / f"ransomware_rwguard_features_{self.time_window}sec.csv"
        # ransomware_features_path = ATTACKS_PATH / "functional_split_RWGuard_8" / f"ransomware_rwguard_features_{self.time_window}sec.csv"

        # Load datasets
        benign_x, benign_y = self.load_csv_features(benign_features_path)
        ransomware_x, ransomware_y = self.load_csv_features(ransomware_features_path)

        X = np.concatenate((benign_x, ransomware_x))
        y = np.concatenate((benign_y, ransomware_y))

        # Train-test split (same as training)
        _, test_x, _, test_y = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

        # Load saved model
        model_path = SAVED_MODELS_PATH / saved_model
        if not model_path.exists():
            print(f"    ❌ No saved model found at {model_path}\n")
            return

        model = joblib.load(model_path)
        print(f"    ✅ Loaded model from {model_path}\n")

        # Predictions
        predictions = model.predict(test_x)

        # Basic metrics
        accuracy = metrics.accuracy_score(test_y, predictions)
        precision = metrics.precision_score(test_y, predictions, average='weighted', zero_division=0)
        recall = metrics.recall_score(test_y, predictions, average='weighted', zero_division=0)
        f1 = metrics.f1_score(test_y, predictions, average='weighted', zero_division=0)

        print("\n📈 Performance Metrics:")
        print(f"    Accuracy : {accuracy:.4f}")
        print(f"    Precision: {precision:.4f}")
        print(f"    Recall   : {recall:.4f}")
        print(f"    F1-score : {f1:.4f}")

        # Detailed classification report
        print("\n📄 Classification Report:")
        print(metrics.classification_report(test_y, predictions, zero_division=0))

        # Confusion matrix
        cm = metrics.confusion_matrix(test_y, predictions)
        print("\n🔍 Confusion Matrix:")
        print(cm)

        # Optional ROC-AUC (for binary classification)
        if len(set(test_y)) == 2:
            y_prob = model.predict_proba(test_x)[:, 1]
            roc_auc = metrics.roc_auc_score(test_y, y_prob)
            print(f"\n🏅 ROC AUC: {roc_auc:.4f}")

        # --- Save results to CSV ---
        os.makedirs(results_file.parent, exist_ok=True)

        file_exists = results_file.exists()
        with open(results_file, "a", newline="") as fp:
            writer = csv.writer(fp)

            # Write header if file is new
            if not file_exists:
                writer.writerow([
                    "Model", "Model Hash", "Accuracy",
                    "Precision", "Recall", "F1_score",
                    "ROC_AUC", "Confusion_Matrix"
                ])

            # Write row of results
            writer.writerow([
                model_name,
                saved_model,
                f"{accuracy:.4f}",
                f"{precision:.4f}",
                f"{recall:.4f}",
                f"{f1:.4f}",
                f"{roc_auc:.4f}" if roc_auc != "" else "",
                cm.tolist()
            ])

        print(f"\n    💾 Results saved to {results_file}")
            