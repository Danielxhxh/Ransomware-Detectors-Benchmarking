from collections import defaultdict
import os
import numpy as np
from sklearn import metrics
from models import MODEL_REGISTRY
from sklearn.model_selection import train_test_split
import gzip
import sys
import json
import csv
import joblib
from scripts.utils.load_config import config, BASE_DIR
from scripts.utils.calculate_hash import calculate_hash
import re


LOGS_PATH = BASE_DIR / 'data' / 'ShieldFS-dataset'
FEATURES_PATH = BASE_DIR / 'datasets' / 'ShieldFS' / 'process_centric' 
SAVED_MODELS_PATH = BASE_DIR / 'saved_models'
TIER = config['ShieldFS']['tiers']

ACTIONS = {
    'FILE_READ': ['IRP_MJ_READ'],
    'FILE_WRITE': ['IRP_MJ_WRITE'],
    'FILE_RENAME_MOVED': ['IRP_MJ_SET_INFORMATION'],
    'DIRECTORY_LISTING': ['IRP_MJ_DIRECTORY_CONTROL.IRP_MN_QUERY_DIRECTORY'],
}

TICKS_EXP = {
    1: [0.11, 0.13, 0.17, 0.22, 0.28, 0.33, 0.46, 0.63, 0.83, 1, 1.37,
        1.78, 2.3, 3, 3.92, 5, 6.66, 8.66, 11.25, 14.68, 19.1, 24.71, 32.1, 41, 54, 70.5, 91, 100],
    2: [0.13,  0.22, 0.37,  0.63, 1, 1.79, 3, 5, 8.65, 14.68, 24.71, 41, 70.5, 100],
    3: [0.17, 0.37, 0.83, 1.78, 3.92, 8.66, 19.1, 41, 100],
    4: [0.22, 0.63, 1.78, 5, 14.68, 41, 100],
    5: [0.28, 1, 3.92, 14.68, 54, 100],
    6: [0.37, 1.78, 8.65, 41, 100],
    7: [0.48, 3, 19.1, 100],
    8: [0.63, 5, 41, 100],
    9: [0.83, 8.66, 100],
    10: [1, 14.68, 100],
    11: [1.37, 24.7, 100],
    12: [1.78, 41, 100],
    13: [2.3, 70.5, 100],
    14: [3, 100],
    15: [3.92, 100],
    16: [5, 100],
    17: [6.66, 100],
    18: [8.66, 100],
    19: [11.25, 100],
    20: [14.68, 100],
    21: [19.1, 100],
    22: [24.71, 100],
    23: [32.1, 100],
    24: [41, 100],
    25: [54, 100],
    26: [70.5, 100],
    27: [91, 100],
    28: [100]
}

SESSION_PID_MAP = {
    '480bd1ecb1b969e6677c1e11a30cd985e4244e5de04956e2dbb0e6b97c42027e.gz': '2616',
    '09c278fc0ae3a36170a71e65bba9f92da086fca941ba93051811bf16c6b67f64.gz': '2060',
    '0d6fb25cde440df0d2b6a676e86b23c47c298f60f8ec461805cc4cd77dd9f730.gz': '3680',
    'c80d611b38c6ea23cf9d564111a24f245f48df48a5341da896912054dd7d9529.gz': '3684'
}

class ShieldFS:
    @staticmethod
    def calculate_file_type_coverage(total_files_accessed, currently_seen_extensions, extension_counts_dict):
        sum_counts = sum(extension_counts_dict.get(ext, 0) for ext in currently_seen_extensions)
        return float(total_files_accessed) / float(sum_counts) if sum_counts != 0 else 0

    @staticmethod
    def load_machine_statistics_benign(machine):
        statistics_file = BASE_DIR / 'utilities' / 'ShieldFS' / 'statistics'/ 'machine_statistics.txt'
        with open(statistics_file, 'r') as fp:
            for ln in fp:
                try:
                    els = ln.split('\t')
                    if els[0] == machine:
                        return int(els[1]), int(els[2]), json.loads(els[3])
                except:
                    pass

    @staticmethod
    def load_machine_statistics_ransomware():
        statistics_file = BASE_DIR / 'utilities' / 'ShieldFS' / 'statistics' / 'machine_statistics_virtual.txt'
        with open(statistics_file, 'r') as fp:
            for ln in fp:
                try:
                    els = ln.split('\t')
                    return int(els[1]), int(els[2]), json.loads(els[3])
                except:
                    pass

    @staticmethod
    def load_csv_features(path, feature_cols=[0,1,2,3,4,5], label_col=6):
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

    def generate_all_ticks_csv(self, dataset):
        folder = FEATURES_PATH / dataset / f"tier{TIER}"
        all_ticks_path = folder / "all_ticks.csv"

        def extract_tick_number(path):
            match = re.search(r"tick(\d+)\.csv", str(path))
            return int(match.group(1)) if match else -1

        tick_files = sorted(folder.glob("tick*.csv"), key=extract_tick_number)
        if not tick_files:
            print(f"No tick files found in {folder}")
            return

        with open(all_ticks_path, 'w', newline='') as out_fp:
            writer = csv.writer(out_fp)

            for tick_file in tick_files:
                try:
                    with open(tick_file, 'r', newline='') as in_fp:
                        reader = csv.reader(in_fp)
                        # NO next(reader) because no header
                        for row in reader:
                            writer.writerow(row)
                except Exception as e:
                    print(f"Failed to read {tick_file}: {e}")

        print(f"Generated {all_ticks_path}")

    def extract_ransomware_features(self):
        features_path = FEATURES_PATH / "ransomware"
        ransomware_logs_path = LOGS_PATH / "ransomware-irp-logs"
        number_folders, number_files, extension_counts = self.load_machine_statistics_ransomware()

        for session_name in os.listdir(ransomware_logs_path):
            print("The ransomware log is: ", session_name)

            session_path = ransomware_logs_path / session_name
            current_tick = 0
            features = defaultdict(list)
            seen_files = set()
            seen_extensions = set()
            num_folder_listings = 0
            num_files_read = 0
            num_files_written = 0
            num_files_renamedmoved = 0
            write_entropy = 0.0
            nr_files_accessed = 0

            try:
                if session_name.endswith(".gz"):
                    ransomware_pid = SESSION_PID_MAP.get(session_name)
                    with gzip.open(session_path, 'r') as fin:
                        for line in fin:
                            try:
                                line = line.decode("utf-8").split("\t")
                                if len(line) != 23:
                                    continue

                                major_op = line[7].strip()
                                minor_op = line[8].strip()
                                file_accessed = line[22].strip()
                                process_pid = line[4].split('.')[0].strip()
                                m_m = major_op + '.' + minor_op
                                change = False

                                if process_pid == ransomware_pid:
                                    if major_op in ACTIONS['FILE_READ']:
                                        num_files_read += 1
                                        change = True

                                    if major_op in ACTIONS['FILE_WRITE']:
                                        num_files_written += 1
                                        write_entropy += float(line[21])
                                        change = True

                                    if major_op in ACTIONS['FILE_RENAME_MOVED']:
                                        num_files_renamedmoved += 1
                                        change = True

                                    if m_m in ACTIONS['DIRECTORY_LISTING']:
                                        num_folder_listings += 1
                                        change = True

                                    if change and file_accessed not in ('0.000000000000000', 'cannot get name'):
                                        if file_accessed not in seen_files:
                                            seen_files.add(file_accessed)
                                            nr_files_accessed += 1

                                        extension = os.path.splitext(file_accessed)[1]
                                        seen_extensions.add(extension)

                                    percentage_file_accessed = float(len(seen_files)) / float(number_files) * 100
                                    percentage_file_accessed = round(percentage_file_accessed, 2)

                                    if change and current_tick < len(TICKS_EXP[TIER]) and percentage_file_accessed >= TICKS_EXP[TIER][current_tick]:
                                        f_coverage = self.calculate_file_type_coverage(nr_files_accessed, seen_extensions, extension_counts)
                                        a = float(num_folder_listings) / float(number_folders)
                                        b = float(num_files_read) / float(number_files)
                                        c = float(num_files_written) / float(number_files)
                                        d = float(num_files_renamedmoved) / float(number_files)
                                        e = write_entropy / float(num_files_written) if num_files_written > 0 else 0
                                        features[current_tick].append([a, b, c, d, f_coverage, e, 'M'])

                                        num_folder_listings = 0
                                        num_files_read = 0
                                        num_files_written = 0
                                        num_files_renamedmoved = 0
                                        write_entropy = 0.0
                                        nr_files_accessed = 0
                                        seen_extensions.clear()
                                        seen_files.clear()

                                        current_tick += 1
                            except UnicodeDecodeError:
                                continue
            except Exception:
                continue

            output_dir = features_path / f"tier{TIER}"
            os.makedirs(output_dir, exist_ok=True)

            for tick, feature_list in features.items():
                output_file = output_dir / f"tick{tick}.csv"
                with open(output_file, 'a', newline='') as fp:
                    writer = csv.writer(fp)
                    writer.writerows(feature_list)

            print('Finished Ransomware Session', session_name)

    def extract_benign_features(self):
        features_path = FEATURES_PATH / "benign"
        benign_logs_path = LOGS_PATH / "benign-irp-logs"

        for machine_name in os.listdir(benign_logs_path):
            machine_path = benign_logs_path / machine_name
            if not machine_path.is_dir():
                continue

            print(f"Processing machine: {machine_name}")

            number_folders, number_files, extension_counts = self.load_machine_statistics_benign(machine_name)

            for session_name in os.listdir(machine_path):
                session_folder_path = machine_path / session_name
                if not session_folder_path.is_dir():
                    continue

                print(f"Processing session: {session_name}")

                features = defaultdict(list)

                # Initialize per-process dicts 
                num_folder_listings = defaultdict(int)
                num_files_read = defaultdict(int)
                num_files_written = defaultdict(int)
                num_files_renamedmoved = defaultdict(int)
                write_entropy = defaultdict(float)
                seen_extensions = defaultdict(set)
                seen_files = defaultdict(set)
                nr_files_accessed = defaultdict(int)
                process_ticks = defaultdict(int)
                percentage_file_accessed = defaultdict(float)

                for inFile in os.listdir(session_folder_path):
                    if inFile.endswith(".gz"):
                        filetoProcess = session_folder_path / inFile
                        try:
                            with gzip.open(filetoProcess, 'rt', encoding='utf-8') as fin:
                                for line in fin:
                                    line = line.strip().split('\t')
                                    if len(line) != 23:
                                        continue

                                    major_op = line[7].strip()
                                    minor_op = line[8].strip()
                                    process_pid = line[4].split('.')[0].strip()
                                    file_accessed = line[22].strip()
                                    m_m = f"{major_op}.{minor_op}"
                                    change = False

                                    if major_op in ACTIONS['FILE_READ']:
                                        num_files_read[process_pid] += 1
                                        change = True

                                    if major_op in ACTIONS['FILE_WRITE']:
                                        num_files_written[process_pid] += 1
                                        write_entropy[process_pid] += float(line[21])
                                        change = True

                                    if major_op in ACTIONS['FILE_RENAME_MOVED']:
                                        num_files_renamedmoved[process_pid] += 1
                                        change = True

                                    if m_m in ACTIONS['DIRECTORY_LISTING']:
                                        num_folder_listings[process_pid] += 1
                                        change = True

                                    if change and file_accessed not in ('0.000000000000000', 'cannot get name'):
                                        if file_accessed not in seen_files[process_pid]:
                                            seen_files[process_pid].add(file_accessed)
                                            nr_files_accessed[process_pid] += 1

                                        # Extract file extension
                                        extension = os.path.splitext(file_accessed)[1]
                                        seen_extensions[process_pid].add(extension)

                                        # Update percentage file accessed
                                        p_f = float(len(seen_files[process_pid])) / number_files * 100
                                        percentage_file_accessed[process_pid] = round(p_f, 2)
                                    
                                    # Check if current process tick threshold met, and then if it's in the current bounds
                                    current_tick = process_ticks[process_pid]
                                    if change and current_tick < len(TICKS_EXP[TIER]) and percentage_file_accessed[process_pid] >= TICKS_EXP[TIER][current_tick]:
                                        f_coverage = self.calculate_file_type_coverage(nr_files_accessed[process_pid], seen_extensions[process_pid], extension_counts)
                                        a = float(num_folder_listings[process_pid]) / float(number_folders)
                                        b = float(num_files_read[process_pid]) / float(number_files)
                                        c = float(num_files_written[process_pid]) / float(number_files)
                                        d = float(num_files_renamedmoved[process_pid]) / float(number_files)
                                        e = (write_entropy[process_pid] / float(num_files_written[process_pid])) if num_files_written[process_pid] > 0 else 0

                                        features[current_tick].append([a, b, c, d, f_coverage, e, 'N'])

                                        # Reset counters for next tick
                                        num_folder_listings[process_pid] = 0
                                        num_files_read[process_pid] = 0
                                        num_files_written[process_pid] = 0
                                        num_files_renamedmoved[process_pid] = 0
                                        write_entropy[process_pid] = 0.0
                                        nr_files_accessed[process_pid] = 0
                                        seen_extensions[process_pid].clear()
                                        seen_files[process_pid].clear()
                                        percentage_file_accessed[process_pid] = 0

                                        process_ticks[process_pid] += 1

                        except Exception as e:
                            print(f"Error processing file {filetoProcess}: {e}")

                # Write features per tick to disk
                output_dir = features_path / f"tier{TIER}"
                os.makedirs(output_dir, exist_ok=True)

                for tick, feature_list in features.items():
                    output_file = output_dir / f"tick{tick}.csv"
                    with open(output_file, 'a', newline='') as fp:
                        writer = csv.writer(fp)
                        writer.writerows(feature_list)

                print(f'Finished session {session_name}')

    def train_model(self, model_name):
        print("Starting ShieldFS training")
        benign_features_path = FEATURES_PATH / "benign" / f"tier{TIER}" / "all_ticks.csv"
        ransomware_features_path = FEATURES_PATH / "ransomware" / f"tier{TIER}" / "all_ticks.csv"

        # Check if files exist, else generate them
        if not benign_features_path.exists():
            self.generate_all_ticks_csv("benign")

        if not ransomware_features_path.exists():
            self.generate_all_ticks_csv("ransomware")

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
        model_path = SAVED_MODELS_PATH / f"{calculate_hash('ShieldFS')}.pkl"
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        model.save(model_path)
        print(f"Model saved to {model_path}")

        #  Evaluate model 
        print("Evaluating model on test set...")
        predictions = model.predict(test_x)
        accuracy = metrics.accuracy_score(test_y, predictions)
        print(f"🔎 Test Accuracy: {accuracy:.4f}")



    def evaluate(self, saved_model):
        print(f"📊 Evaluating saved '{saved_model}' model")

        # Paths to features
        benign_features_path = FEATURES_PATH / "benign" / f"tier{TIER}" / "all_ticks.csv"
        ransomware_features_path = FEATURES_PATH / "ransomware" / f"tier{TIER}" / "all_ticks.csv"

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
            print(f"❌ No saved model found at {model_path}")
            return

        model = joblib.load(model_path)
        print(f"✅ Loaded model from {model_path}")

        # Predictions
        predictions = model.predict(test_x)

        # Basic metrics
        accuracy = metrics.accuracy_score(test_y, predictions)
        precision = metrics.precision_score(test_y, predictions, average='weighted', zero_division=0)
        recall = metrics.recall_score(test_y, predictions, average='weighted', zero_division=0)
        f1 = metrics.f1_score(test_y, predictions, average='weighted', zero_division=0)

        print("\n📈 Performance Metrics:")
        print(f"  Accuracy : {accuracy:.4f}")
        print(f"  Precision: {precision:.4f}")
        print(f"  Recall   : {recall:.4f}")
        print(f"  F1-score : {f1:.4f}")

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
        