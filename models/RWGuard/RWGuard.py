from collections import defaultdict
import numpy as np
from sklearn import metrics
from sklearn.model_selection import train_test_split
from ml_models import MODEL_REGISTRY
import yaml
import os
import gzip
import sys
import csv
from datetime import datetime
from pathlib import Path
from scripts.utils.load_config import config, BASE_DIR

TIME_WINDOW = config['time_window'] 
LOGS_PATH = BASE_DIR / 'datasets' / 'raw' / 'ShieldFS-dataset' 
FEATURES_PATH = BASE_DIR / 'datasets' / 'features' / 'RWGuard'
SAVED_MODELS_PATH = BASE_DIR / 'saved_models'

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
        print("Starting RWGuard training")
        benign_features_path = FEATURES_PATH / f"benign_rwguard_features_{self.time_window}sec.csv"
        ransomware_features_path = FEATURES_PATH / f"ransomware_rwguard_features_{self.time_window}sec.csv"

        #  Load and merge datasets 
        benign_x, benign_y = self.load_csv_features(benign_features_path)
        ransomware_x, ransomware_y = self.load_csv_features(ransomware_features_path)

        X = np.concatenate((benign_x, ransomware_x))
        y = np.concatenate((benign_y, ransomware_y))
        print(f"Loaded {len(X)} total samples ({len(benign_x)} benign, {len(ransomware_x)} ransomware)")

        #  Split data 
        train_x, test_x, train_y, test_y = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
        print(f"Training set size: {len(train_x)}, Testing set size: {len(test_x)}")

        #  Train model 
        model = MODEL_REGISTRY[model_name]()
        print(f"Training '{model_name}' model...")
        model.train(train_x, train_y)
        print("Model training completed")

        #  Save model 
        model_path = SAVED_MODELS_PATH / f"{model_name}_rwguard_{self.time_window}sec.pkl"
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        model.save(model_path)
        print(f"Model saved to {model_path}")

        #  Evaluate model 
        print("Evaluating model on test set...")
        predictions = model.predict(test_x)
        accuracy = metrics.accuracy_score(test_y, predictions)
        print(f"🔎 Test Accuracy: {accuracy:.4f}")
