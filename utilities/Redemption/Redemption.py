from collections import defaultdict
import numpy as np
from sklearn import metrics
from sklearn.model_selection import train_test_split
import joblib
import os
import gzip
import csv
from datetime import datetime
from typing import Optional, Tuple
from dataclasses import dataclass, field
from scripts.utils.load_config import config, BASE_DIR
from scripts.utils.calculate_hash import calculate_hash

# --- CONFIGURATION & PATHS ---
LOGS_PATH = BASE_DIR / 'data' / 'ShieldFS-dataset' 
FEATURES_PATH = BASE_DIR / 'datasets' / 'Redemption'
SAVED_MODELS_PATH = BASE_DIR / 'saved_models'
RESULTS_PATH = BASE_DIR / 'results' / 'Redemption'

# Ensure output directory exists
os.makedirs(FEATURES_PATH, exist_ok=True)

ACTIONS = {
    'FILE_READ': ['IRP_MJ_READ'],
    'FILE_WRITE': ['IRP_MJ_WRITE'],
    'FILE_RENAME_MOVED': ['IRP_MJ_SET_INFORMATION'],
    'DIRECTORY_LISTING': ['IRP_MJ_DIRECTORY_CONTROL.IRP_MN_QUERY_DIRECTORY'],
}

EXTENSION_CATEGORY = {
    "office_doc": {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt"},
    "pdf": {".pdf"},
    "text": {".txt", ".rtf"},
    "image": {".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tiff", ".svg", ".webp"},
    "audio": {".mp3", ".wav", ".flac", ".aac", ".ogg"},
    "video": {".mp4", ".avi", ".mov", ".mkv", ".wmv"},
    "archive": {".zip", ".rar", ".7z", ".tar", ".gz"},
    "binary": {".exe", ".dll", ".bin", ".manifest", ".vdf", ".nls"},
    "code": {".py", ".c", ".cpp", ".java", ".js", ".cs", ".html", ".css"},
    "config": {".log", ".ini", ".cfg", ".json", ".xml"},
}
EXTENSION_LOOKUP = {ext: category for category, exts in EXTENSION_CATEGORY.items() for ext in exts}

# Ransomware PIDs for the labeled dataset
SESSION_PID_MAP = {
    '480bd1ecb1b969e6677c1e11a30cd985e4244e5de04956e2dbb0e6b97c42027e.gz': '2616',
    '09c278fc0ae3a36170a71e65bba9f92da086fca941ba93051811bf16c6b67f64.gz': '2060',
    '0d6fb25cde440df0d2b6a676e86b23c47c298f60f8ec461805cc4cd77dd9f730.gz': '3680',
    'c80d611b38c6ea23cf9d564111a24f245f48df48a5341da896912054dd7d9529.gz': '3684'
}

@dataclass
class FileActivity:
    # r1: Map offset -> entropy value
    read_history: dict = field(default_factory=dict)
    entropy_ratio: float = 0.0
    
    # r2: Track modified bytes (unique 4KB blocks)
    modified_blocks: set = field(default_factory=set)

@dataclass
class ProcessProfile:
    files: dict = field(default_factory=dict)   # {filename: FileActivity}
    
    # r3
    delete_operation: int = 0
    # r4
    dir_writes: dict = field(default_factory=lambda: defaultdict(set))
    dir_traversals: float = 0.0
    # r5
    file_classes: set = field(default_factory=set)
    convert_type: int = 0 
    # r6
    last_write: Tuple[Optional[datetime], str] = (None, "")
    elapsed_time: Optional[float] = None
    access_frequency: Optional[float] = None


class Redemption:
    def __init__(self):
        self.session_pid_map = SESSION_PID_MAP
        # Fixed weights from the Redemption paper
        self.weights = {
            "r1_entropy": 0.9,
            "r2_overwrite": 1.0,
            "r3_delete": 0.6,
            "r4_traversal": 1.0,
            "r5_ext": 0.7,
            "r6_freq": 1.0
        }
        self.weight_sum = sum(self.weights.values()) # 5.2
        self.threshold = 0.12

    @staticmethod
    def _get_file_class(filename):
        _, ext = os.path.splitext(filename.lower())
        return EXTENSION_LOOKUP.get(ext, "other")
    
    @staticmethod
    def _date_diff_in_seconds(dt2, dt1) -> Optional[float]:
        delta = (dt2 - dt1).total_seconds()
        return delta if delta >= 0 else None
    
    @staticmethod
    def _rreplace(s, old, new):
        return (s[::-1].replace(old[::-1], new[::-1], 1))[::-1]
    
    @staticmethod
    def _safe_float(value: str) -> Optional[float]:
        try:
            return float(value.strip())
        except ValueError:
            return None
            
    def _load_machine_stats(self, machine_name):
        """Loads file sizes from machines-statistics for r2 calculation."""
        stats_path = BASE_DIR / 'data' / 'machines-statistics' / f"{machine_name}.csv"
        file_sizes = {}
        if os.path.exists(stats_path):
            try:
                with open(stats_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        parts = line.strip().split(',')
                        if len(parts) >= 3:
                            path = parts[0].lower().strip()
                            try:
                                size = int(parts[2])
                                file_sizes[path] = size
                            except ValueError:
                                pass
            except Exception:
                pass
        return file_sizes

    def _update_access_frequency(self, process: ProcessProfile, parsed_time: datetime, file_accessed: str):
        if process.last_write[1] == file_accessed:
            return

        if process.last_write[0] is not None:
            process.elapsed_time = self._date_diff_in_seconds(parsed_time, process.last_write[0])
            if process.elapsed_time is not None:
                # Delta cap of 0.1s for "high frequency"
                delta_cap = 0.1
                process.access_frequency = 1 - min(process.elapsed_time / delta_cap, 1)
            else:
                process.access_frequency = None
        else:
            process.elapsed_time = None
            process.access_frequency = None

        process.last_write = (parsed_time, file_accessed)

    def extract_benign_features(self):
        output_file = FEATURES_PATH / "benign_redemption_features.csv"
        benign_logs_path = LOGS_PATH / "benign-irp-logs"
        
        # Write Header
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['r1_entropy', 'r2_overwrite', 'r3_delete', 'r4_traversal', 'r5_ext', 'r6_freq', 'malice_score', 'label'])

        for machine_name in os.listdir(benign_logs_path):
            machine_path = benign_logs_path / machine_name
            if not machine_path.is_dir():
                continue

            print(f"Processing machine: {machine_name}")
            # Load file sizes for this machine (needed for r2)
            machine_file_sizes = self._load_machine_stats(machine_name)

            for session_name in os.listdir(machine_path):
                session_folder_path = machine_path / session_name
                if not session_folder_path.is_dir():
                    continue

                print(f"  Processing session: {session_name}")
                process_state = defaultdict(ProcessProfile)
                batch_features = []

                for inFile in os.listdir(session_folder_path):
                    if not inFile.endswith(".gz"):
                        continue
                        
                    filetoProcess = session_folder_path / inFile
                    try:
                        with gzip.open(filetoProcess, 'rt', encoding='utf-8', errors='ignore') as fin:
                            for line in fin:
                                line = line.strip().split('\t')
                                if len(line) != 23:
                                    continue
                                
                                # 1. Parse Args (Offset/Length)
                                try:
                                    offset_hex = line[14].strip()
                                    offset = int(offset_hex, 16) if offset_hex.startswith('0x') else int(offset_hex)
                                    length_hex = line[20].strip()
                                    length = int(length_hex, 16) if length_hex.startswith('0x') else int(length_hex)
                                except (ValueError, IndexError):
                                    offset, length = 0, 0

                                major_op = line[7].strip()
                                process_pid = line[4].split('.')[0].strip()
                                post_time = self._rreplace(line[3].strip(), ':', '.')
                                parsed_time = datetime.strptime(post_time, '%H:%M:%S.%f')
                                file_accessed = line[22].strip().lower()
                                
                                if file_accessed in ('0.000000000000000', 'cannot get name', ''):
                                    continue

                                process = process_state[process_pid]
                                if file_accessed not in process.files:
                                    process.files[file_accessed] = FileActivity()
                                file_act = process.files[file_accessed]

                                # 2. Handle Read (Entropy History)
                                if major_op in ACTIONS['FILE_READ']:
                                    entropy_val = self._safe_float(line[21])
                                    if entropy_val is not None:
                                        file_act.read_history[offset] = entropy_val

                                # 3. Handle Write (Score Calculation)
                                elif major_op in ACTIONS['FILE_WRITE']:
                                    entropy_val = self._safe_float(line[21])
                                    
                                    # r1: Entropy Ratio
                                    prev_read = file_act.read_history.get(offset)
                                    if prev_read and entropy_val and entropy_val > prev_read:
                                        file_act.entropy_ratio = 1.0 - (prev_read / entropy_val)
                                    else:
                                        file_act.entropy_ratio = 0.0

                                    # r2: Content Overwrite (Skipping calc per request, defaulting to 0)
                                    # Logic exists in previous answers if needed
                                    r2 = 0.0 

                                    # r4: Directory Traversal
                                    dir_path, fname = os.path.split(file_accessed.replace("\\", "/"))
                                    process.dir_writes[dir_path].add(fname)
                                    r4 = min(len(process.dir_writes[dir_path]) / 50.0, 1.0)

                                    # r5: Type Conversion
                                    process.file_classes.add(self._get_file_class(file_accessed))
                                    r5 = 1.0 if len(process.file_classes) > 1 else 0.0

                                    # r6: Access Frequency
                                    self._update_access_frequency(process, parsed_time, file_accessed)
                                    r6 = process.access_frequency if process.access_frequency else 0.0

                                    # r3: Delete
                                    r3 = 1.0 if process.delete_operation > 0 else 0.0

                                    # Malice Score (MSC)
                                    numerator = (0.9 * file_act.entropy_ratio) + (1.0 * r2) + \
                                                (0.6 * r3) + (1.0 * r4) + (0.7 * r5) + (1.0 * r6)
                                    msc = numerator / self.weight_sum
                                    
                                    # Collect Row
                                    batch_features.append([
                                        f"{file_act.entropy_ratio:.4f}", f"{r2:.4f}", f"{r3:.4f}", 
                                        f"{r4:.4f}", f"{r5:.4f}", f"{r6:.4f}", 
                                        f"{msc:.4f}", 'N'
                                    ])

                                elif major_op in ACTIONS['FILE_RENAME_MOVED']:
                                    process.delete_operation += 1
                                    
                    except Exception as e:
                        print(f"    Error reading {inFile}: {e}")

                # Flush batch to disk per session
                if batch_features:
                    with open(output_file, 'a', newline='') as f:
                        csv.writer(f).writerows(batch_features)
                    batch_features.clear()
                    
                print(f"    Finished session {session_name}")

    def extract_ransomware_features(self):
        output_file = FEATURES_PATH / "ransomware_redemption_features.csv"
        logs_path = LOGS_PATH / "ransomware-irp-logs"
        
        # Write Header
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['r1_entropy', 'r2_overwrite', 'r3_delete', 'r4_traversal', 'r5_ext', 'r6_freq', 'malice_score', 'label'])

        for session_name in os.listdir(logs_path):
            session_path = logs_path / session_name
            if not session_path.is_file() or not session_name.endswith('.gz'):
                continue

            print(f"Processing ransomware session: {session_name}")
            ransomware_pid = self.session_pid_map.get(session_name)
            
            # Since ransomware logs don't have corresponding "machines-statistics", r2 will default to 0/heuristic
            machine_file_sizes = {} 

            process_state = defaultdict(ProcessProfile)
            batch_features = []

            try:
                with gzip.open(session_path, 'rt', encoding='utf-8', errors='ignore') as fin:
                    # Skip header lines if present (usually 2 in ShieldFS datasets)
                    next(fin, None)
                    next(fin, None)

                    for line in fin:
                        line = line.strip().split('\t')
                        if len(line) != 23:
                            continue

                        # Filter by Ransomware PID
                        current_pid = line[4].split('.')[0].strip()
                        if ransomware_pid and current_pid != ransomware_pid:
                            continue
                            
                        # 1. Parse Args
                        try:
                            offset_hex = line[14].strip()
                            offset = int(offset_hex, 16) if offset_hex.startswith('0x') else int(offset_hex)
                        except (ValueError, IndexError):
                            offset = 0

                        major_op = line[7].strip()
                        post_time = self._rreplace(line[3].strip(), ':', '.')
                        parsed_time = datetime.strptime(post_time, '%H:%M:%S.%f')
                        file_accessed = line[22].strip().lower()

                        if file_accessed in ('0.000000000000000', 'cannot get name', ''):
                            continue

                        process = process_state[current_pid]
                        if file_accessed not in process.files:
                            process.files[file_accessed] = FileActivity()
                        file_act = process.files[file_accessed]

                        if major_op in ACTIONS['FILE_READ']:
                            entropy_val = self._safe_float(line[21])
                            if entropy_val is not None:
                                file_act.read_history[offset] = entropy_val

                        elif major_op in ACTIONS['FILE_WRITE']:
                            entropy_val = self._safe_float(line[21])
                            
                            # r1
                            prev_read = file_act.read_history.get(offset)
                            if prev_read and entropy_val and entropy_val > prev_read:
                                file_act.entropy_ratio = 1.0 - (prev_read / entropy_val)
                            else:
                                file_act.entropy_ratio = 0.0
                            
                            # r2 (default 0 as requested)
                            r2 = 0.0
                            
                            # r4
                            dir_path, fname = os.path.split(file_accessed.replace("\\", "/"))
                            process.dir_writes[dir_path].add(fname)
                            r4 = min(len(process.dir_writes[dir_path]) / 50.0, 1.0)
                            
                            # r5
                            process.file_classes.add(self._get_file_class(file_accessed))
                            r5 = 1.0 if len(process.file_classes) > 1 else 0.0
                            
                            # r6
                            self._update_access_frequency(process, parsed_time, file_accessed)
                            r6 = process.access_frequency if process.access_frequency else 0.0
                            
                            # r3
                            r3 = 1.0 if process.delete_operation > 0 else 0.0

                            # MSC
                            numerator = (0.9 * file_act.entropy_ratio) + (1.0 * r2) + \
                                        (0.6 * r3) + (1.0 * r4) + (0.7 * r5) + (1.0 * r6)
                            msc = numerator / self.weight_sum

                            batch_features.append([
                                f"{file_act.entropy_ratio:.4f}", f"{r2:.4f}", f"{r3:.4f}", 
                                f"{r4:.4f}", f"{r5:.4f}", f"{r6:.4f}", 
                                f"{msc:.4f}", 'M'
                            ])

                        elif major_op in ACTIONS['FILE_RENAME_MOVED']:
                            process.delete_operation += 1

                # Flush to disk
                if batch_features:
                    with open(output_file, 'a', newline='') as f:
                        csv.writer(f).writerows(batch_features)
                
                print(f"Finished session {session_name}")

            except Exception as e:
                print(f"Error processing {session_name}: {e}")

    def evaluate(self):            
            # Path to results
            results_file = RESULTS_PATH / "evaluation_results.csv"
            os.makedirs(RESULTS_PATH, exist_ok=True)
            
            # Paths to features
            benign_features_path = FEATURES_PATH / "benign_redemption_features.csv"
            ransomware_features_path = FEATURES_PATH / "ransomware_redemption_features.csv"
            
            y_true = []
            y_pred = []
            y_scores = [] # Malice scores act as "probabilities" for ROC-AUC

            # Helper to process a file
            def process_file(path):
                if not path.exists():
                    print(f"    ⚠️ Warning: File not found {path}")
                    return

                print(f"    📂 Loading features from: {path.name}")
                with open(path, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        try:
                            # 1. Get the Score
                            score = float(row['malice_score'])
                            
                            # 2. Get the Ground Truth Label
                            label_str = row['label'].strip().upper()
                            if label_str in ['N', 'BENIGN']:
                                ground_truth = 0
                            elif label_str in ['M', 'RANSOMWARE']:
                                ground_truth = 1
                            else:
                                continue 

                            # 3. Apply Threshold Logic (Redemption's "Model")
                            # If score > 0.12 -> Predict Malicious (1), else Benign (0)
                            prediction = 1 if score > self.threshold else 0

                            y_true.append(ground_truth)
                            y_pred.append(prediction)
                            y_scores.append(score)
                            
                        except ValueError:
                            continue 

            # Process both datasets
            process_file(benign_features_path)
            process_file(ransomware_features_path)

            if not y_true:
                print("    ❌ No valid data found to evaluate.")
                return

            # --- Calculate Metrics (Same structure as RWGuard) ---
            y_true = np.array(y_true)
            y_pred = np.array(y_pred)
            y_scores = np.array(y_scores)

            # Basic metrics
            accuracy = metrics.accuracy_score(y_true, y_pred)
            # Using 'weighted' average to match RWGuard output
            precision = metrics.precision_score(y_true, y_pred, average='weighted', zero_division=0)
            recall = metrics.recall_score(y_true, y_pred, average='weighted', zero_division=0)
            f1 = metrics.f1_score(y_true, y_pred, average='weighted', zero_division=0)

            print("\n📈 Performance Metrics:")
            print(f"    Accuracy : {accuracy:.4f}")
            print(f"    Precision: {precision:.4f}")
            print(f"    Recall   : {recall:.4f}")
            print(f"    F1-score : {f1:.4f}")

            # Detailed classification report
            print("\n📄 Classification Report:")
            print(metrics.classification_report(y_true, y_pred, zero_division=0))

            # Confusion matrix
            cm = metrics.confusion_matrix(y_true, y_pred)
            print("\n🔍 Confusion Matrix:")
            print(cm)

            # ROC-AUC calculation
            roc_auc = ""
            if len(set(y_true)) == 2:
                try:
                    # Use the raw malice score as the "probability"
                    roc_auc = metrics.roc_auc_score(y_true, y_scores)
                    print(f"\n🏅 ROC AUC: {roc_auc:.4f}")
                except Exception:
                    pass

            # --- Save results to CSV (Same columns as RWGuard) ---
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
                # For "Model Hash", we record the Threshold used since there is no saved model file
                writer.writerow([
                    "Redemption_Heuristic",
                    f"Threshold={self.threshold}",
                    f"{accuracy:.4f}",
                    f"{precision:.4f}",
                    f"{recall:.4f}",
                    f"{f1:.4f}",
                    f"{roc_auc:.4f}" if isinstance(roc_auc, float) else "",
                    cm.tolist()
                ])

            print(f"\n    💾 Results saved to {results_file}")

