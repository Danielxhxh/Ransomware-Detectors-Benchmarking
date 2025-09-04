import os
import gzip
import csv
import numpy as np
from collections import defaultdict
from sklearn import metrics
import joblib
from scripts.utils.load_config import BASE_DIR
from scripts.utils.calculate_hash import calculate_hash


FEATURES_PATH = BASE_DIR / 'datasets' / 'Redemption'
LOGS_PATH = BASE_DIR / 'data' / 'ShieldFS-dataset'  # reuse same logs
SAVED_MODELS_PATH = BASE_DIR / 'saved_models'

# Redemption feature weights (from paper)
FEATURE_WEIGHTS = {
    "entropy_ratio": 0.9,
    "content_overwrite": 1.0,
    "delete_operation": 0.6,
    "dir_traversal": 1.0,
    "convert_type": 0.7,
    "access_frequency": 1.0,
}
THRESHOLD = 0.12  # MSC threshold

class Redemption:
    def __init__(self):
        self.weights = FEATURE_WEIGHTS
        self.threshold = THRESHOLD

    def compute_malice_score(self, feature_vec):
        """Compute Redemption's MSC score given feature vector"""
        w_sum = sum(self.weights.values())
        weighted_sum = (
            feature_vec[0] * self.weights["entropy_ratio"] +
            feature_vec[1] * self.weights["content_overwrite"] +
            feature_vec[2] * self.weights["delete_operation"] +
            feature_vec[3] * self.weights["dir_traversal"] +
            feature_vec[4] * self.weights["convert_type"] +
            feature_vec[5] * self.weights["access_frequency"]
        )
        return weighted_sum / w_sum

    def extract_features_from_log(self, log_file, label):
        """
        Extract Redemption feature vector from a single .gz IRP log.
        Feature order:
        [entropy_ratio, content_overwrite, delete_operation,
         dir_traversal, convert_type, access_frequency, label]
        """
        seen_files = set()
        dirs_accessed = defaultdict(set)
        extensions = set()
        last_write_time = None
        del_flag = 0
        content_overwrite = 0.0
        entropy_ratios = []
        write_deltas = []

        with gzip.open(log_file, 'rt', encoding='utf-8') as fin:
            for line in fin:
                parts = line.strip().split('\t')
                if len(parts) != 23:
                    continue

                major_op = parts[7].strip()
                minor_op = parts[8].strip()
                filename = parts[22].strip()
                entropy = float(parts[21])

                if filename in ('0.000000000000000', 'cannot get name', ''):
                    continue

                # Extract extension and directory
                _, ext = os.path.splitext(filename)
                directory = os.path.dirname(filename)

                # Feature 1: Entropy ratio (simplified, track entropy of writes)
                if major_op == "IRP_MJ_WRITE":
                    entropy_ratios.append(entropy)

                    # Feature 6: Access frequency (delta between writes)
                    cur_time = parts[2]  # PreOp Time
                    try:
                        h, m, s, ms = cur_time.split(':')
                        t_ms = int(h)*3600000 + int(m)*60000 + int(s)*1000 + int(ms)
                        if last_write_time is not None:
                            delta = max(1, t_ms - last_write_time)
                            write_deltas.append(1.0 / delta)
                        last_write_time = t_ms
                    except:
                        pass

                    # Track overwrite fraction (approx: count multiple writes to same file)
                    if filename in seen_files:
                        content_overwrite += 1
                    seen_files.add(filename)

                    # Directory traversal
                    dirs_accessed[directory].add(filename)

                    # File type conversion
                    extensions.add(ext)

                # Feature 3: Delete flag
                if major_op == "IRP_MJ_SET_INFORMATION" and "DELETE" in minor_op.upper():
                    del_flag = 1

        # Normalize features
        entropy_ratio = np.mean(entropy_ratios) if entropy_ratios else 0
        content_overwrite = content_overwrite / (len(seen_files) + 1e-6)
        dir_traversal = max(len(files) for files in dirs_accessed.values()) if dirs_accessed else 0
        convert_type = 1 if len(extensions) > 1 else 0
        access_frequency = np.mean(write_deltas) if write_deltas else 0

        return [entropy_ratio, content_overwrite, del_flag,
                dir_traversal, convert_type, access_frequency, label]

    def extract_ransomware_features(self):
        ransomware_logs_path = LOGS_PATH / "ransomware-irp-logs"
        features_path = FEATURES_PATH / "ransomware"
        os.makedirs(features_path, exist_ok=True)

        for session_name in os.listdir(ransomware_logs_path):
            if not session_name.endswith(".gz"):
                continue
            session_path = ransomware_logs_path / session_name
            vec = self.extract_features_from_log(session_path, "M")

            out_file = features_path / "all_features.csv"
            with open(out_file, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(vec)

    def extract_benign_features(self):
        benign_logs_path = LOGS_PATH / "benign-irp-logs"
        features_path = FEATURES_PATH / "benign"
        os.makedirs(features_path, exist_ok=True)

        for machine_name in os.listdir(benign_logs_path):
            machine_path = benign_logs_path / machine_name
            if not machine_path.is_dir():
                continue
            for session_name in os.listdir(machine_path):
                session_folder = machine_path / session_name
                if not session_folder.is_dir():
                    continue
                for log_file in os.listdir(session_folder):
                    if not log_file.endswith(".gz"):
                        continue
                    vec = self.extract_features_from_log(session_folder / log_file, "N")

                    out_file = features_path / "all_features.csv"
                    with open(out_file, 'a', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(vec)

    def train_model(self):
        """
        For Redemption, "training" just saves weights & threshold.
        """
        model_path = SAVED_MODELS_PATH / f"{calculate_hash('Redemption')}.pkl"
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        joblib.dump({"weights": self.weights, "threshold": self.threshold}, model_path)
        print(f"Saved Redemption rule-based model to {model_path}")

    def evaluate(self, dataset="benign"):
        """
        Apply MSC on extracted features and evaluate.
        """
        benign_file = FEATURES_PATH / "benign" / "all_features.csv"
        ransomware_file = FEATURES_PATH / "ransomware" / "all_features.csv"

        X, y, preds = [], [], []
        for path in [benign_file, ransomware_file]:
            with open(path) as f:
                reader = csv.reader(f)
                for row in reader:
                    feats = [float(v) for v in row[:-1]]
                    label = row[-1]
                    score = self.compute_malice_score(feats)
                    pred = "M" if score >= self.threshold else "N"
                    X.append(feats)
                    y.append(label)
                    preds.append(pred)

        # Metrics
        accuracy = metrics.accuracy_score(y, preds)
        precision = metrics.precision_score(y, preds, pos_label="M")
        recall = metrics.recall_score(y, preds, pos_label="M")
        f1 = metrics.f1_score(y, preds, pos_label="M")

        print("\n📈 Redemption Performance:")
        print(f"  Accuracy : {accuracy:.4f}")
        print(f"  Precision: {precision:.4f}")
        print(f"  Recall   : {recall:.4f}")
        print(f"  F1-score : {f1:.4f}")
