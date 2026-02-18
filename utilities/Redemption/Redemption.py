from collections import defaultdict
import numpy as np
from sklearn import metrics
from sklearn.model_selection import train_test_split
import joblib
import os
import gzip
import csv
from datetime import datetime
from typing import Optional, Tuple, List, Set
from dataclasses import dataclass, field
from scripts.utils.load_config import config, BASE_DIR
from scripts.utils.calculate_hash import calculate_hash
from models import MODEL_REGISTRY

TIME_WINDOW = config['Redemption']['time_window']
LOGS_PATH = BASE_DIR / 'data' / 'ShieldFS-dataset' 
FEATURES_PATH = BASE_DIR / 'datasets' / 'Redemption'
SAVED_MODELS_PATH = BASE_DIR / 'saved_models'
RESULTS_PATH = BASE_DIR / 'results' / 'Redemption'
ATTACKS_PATH = BASE_DIR / 'ATTACKS' 

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

SESSION_PID_MAP = {
    '480bd1ecb1b969e6677c1e11a30cd985e4244e5de04956e2dbb0e6b97c42027e.gz': '2616',
    '09c278fc0ae3a36170a71e65bba9f92da086fca941ba93051811bf16c6b67f64.gz': '2060',
    '0d6fb25cde440df0d2b6a676e86b23c47c298f60f8ec461805cc4cd77dd9f730.gz': '3680',
    'c80d611b38c6ea23cf9d564111a24f245f48df48a5341da896912054dd7d9529.gz': '3684'
}

@dataclass
class PersistentState:
    """Data that must persist across time windows (e.g. Read History)."""
    # Map: filename -> offset -> entropy
    read_history: dict = field(default_factory=lambda: defaultdict(dict))
    last_write_time: Optional[datetime] = None
    last_write_file: str = ""

@dataclass
class WindowState:
    """Data that resets every X seconds."""
    # r1: List of entropy ratios calculated for writes in this window
    entropy_ratios: List[float] = field(default_factory=list)
    # r2: Set of modified blocks (unique 4KB chunks). In practice, many logs won't have this info, so we use a simplified count of unique files written to instead.
    modified_blocks: Set[str] = field(default_factory=set)
    # r3: Count of deletes
    delete_count: int = 0
    # r4: Directories written to
    dir_writes: dict = field(default_factory=lambda: defaultdict(set))
    # r5: Extensions written to
    file_classes: Set[str] = field(default_factory=set)
    # r6: List of frequencies calculated in this window
    access_frequencies: List[float] = field(default_factory=list)

class Redemption:
    def __init__(self):
        self.session_pid_map = SESSION_PID_MAP
        self.time_window = TIME_WINDOW
        self.actions = ACTIONS

    @staticmethod
    def _get_file_class(filename):
        _, ext = os.path.splitext(filename.lower())
        return EXTENSION_LOOKUP.get(ext, "other")
    
    @staticmethod
    def _date_diff_in_seconds(dt2, dt1) -> float:
        return (dt2 - dt1).total_seconds()
    
    @staticmethod
    def _rreplace(s, old, new):
        return (s[::-1].replace(old[::-1], new[::-1], 1))[::-1]
    
    @staticmethod
    def _safe_float(value: str) -> Optional[float]:
        try:
            return float(value.strip())
        except ValueError:
            return None
    
    @staticmethod
    def _load_machine_stats(machine_name):
        stats_path = BASE_DIR / 'data' / 'machines-statistics' / f"{machine_name}.csv"
        file_sizes = {}
        if os.path.exists(stats_path):
            try:
                with open(stats_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        parts = line.strip().split(',')
                        if len(parts) >= 3:
                            try:
                                file_sizes[parts[0].lower().strip()] = int(parts[2])
                            except ValueError: pass
            except Exception: pass
        return file_sizes

    def _calculate_window_vector(self, w_state: WindowState) -> List[float]:
        """Condenses the WindowState into a 6-feature vector."""
        
        # r1: Average Entropy Ratio (of writes in this window)
        r1 = sum(w_state.entropy_ratios) / len(w_state.entropy_ratios) if w_state.entropy_ratios else 0.0
        
        # r2: Modified Blocks (Simplified count, usually 0 if stats missing)
        r2 = len(w_state.modified_blocks) # Normalization logic omitted for brevity/speed
        
        # r3: Delete Count (Normalized by arbitrary factor or raw)
        # Paper uses boolean 1.0 if >0. Here we train a model, so raw count or boolean is fine.
        # Let's use boolean to match paper logic closer: 1.0 if deletes occurred, else 0
        r3 = 1.0 if w_state.delete_count > 0 else 0.0
        
        # r4: Directory Traversal Score
        # Max of (unique_files_in_dir / 50) across all dirs touched
        max_traversal = 0.0
        for dir_path, files in w_state.dir_writes.items():
            val = min(len(files) / 50.0, 1.0)
            if val > max_traversal:
                max_traversal = val
        r4 = max_traversal

        # r5: File Type Changes
        r5 = 1.0 if len(w_state.file_classes) > 1 else 0.0
        
        # r6: Average Access Frequency
        r6 = sum(w_state.access_frequencies) / len(w_state.access_frequencies) if w_state.access_frequencies else 0.0
        
        return [r1, r2, r3, r4, r5, r6]

    def extract_benign_features(self):
        output_file = FEATURES_PATH / f"benign_redemption_features_{self.time_window}sec.csv"
        benign_logs_path = LOGS_PATH / "benign-irp-logs"
        
        # We process files and accumulate vectors
        global_features = []

        for machine_name in os.listdir(benign_logs_path):
            machine_path = benign_logs_path / machine_name
            if not machine_path.is_dir(): continue
            print(f"Processing machine: {machine_name}")
            
            # machine_stats = self._load_machine_stats(machine_name) # Used for r2 if needed

            for session_name in os.listdir(machine_path):
                session_folder = machine_path / session_name
                if not session_folder.is_dir(): continue

                print(f"  Processing session: {session_name}")
                
                # State management
                # pid -> PersistentState
                p_states = defaultdict(PersistentState)
                # pid -> WindowState
                w_states = defaultdict(WindowState)
                # pid -> datetime
                previous_time = {}
                current_time = {}

                for inFile in os.listdir(session_folder):
                    if not inFile.endswith(".gz"): continue
                    
                    try:
                        with gzip.open(session_folder / inFile, 'rt', encoding='utf-8', errors='ignore') as fin:
                            for line in fin:
                                line = line.strip().split('\t')
                                if len(line) != 23: continue
                                
                                major_op = line[7].strip()
                                pid = line[4].split('.')[0].strip()
                                post_time = self._rreplace(line[3].strip(), ':', '.')
                                parsed_time = datetime.strptime(post_time, '%H:%M:%S.%f')
                                file_accessed = line[22].strip().lower()
                                
                                if file_accessed in ('0.000000000000000', 'cannot get name', ''): continue

                                # Init Time
                                if pid not in previous_time:
                                    previous_time[pid] = parsed_time
                                current_time[pid] = parsed_time

                                # State Access
                                p_state = p_states[pid]
                                w_state = w_states[pid]

                                # --- Feature Extraction Logic ---

                                # 1. Parse Offset
                                try:
                                    offset_hex = line[14].strip()
                                    offset = int(offset_hex, 16) if offset_hex.startswith('0x') else int(offset_hex)
                                except: offset = 0

                                if major_op in self.actions['FILE_READ']:
                                    ent = self._safe_float(line[21])
                                    if ent is not None:
                                        p_state.read_history[file_accessed][offset] = ent
                                
                                elif major_op in self.actions['FILE_WRITE']:
                                    ent = self._safe_float(line[21])
                                    
                                    # r1: Entropy Ratio
                                    prev_read = p_state.read_history.get(file_accessed, {}).get(offset)
                                    ratio = 0.0
                                    if prev_read and ent and ent > prev_read:
                                        ratio = 1.0 - (prev_read / ent)
                                    w_state.entropy_ratios.append(ratio)

                                    # r2: Modified Blocks (Simplified)
                                    # block_id = f"{file_accessed}_{offset // 4096}"
                                    # w_state.modified_blocks.add(block_id)

                                    # r4: Dir Traversal
                                    dpath, fname = os.path.split(file_accessed.replace("\\", "/"))
                                    w_state.dir_writes[dpath].add(fname)

                                    # r5: Ext
                                    w_state.file_classes.add(self._get_file_class(file_accessed))

                                    # r6: Frequency
                                    if p_state.last_write_time and p_state.last_write_file != file_accessed:
                                        delta = self._date_diff_in_seconds(parsed_time, p_state.last_write_time)
                                        freq = 1 - min(delta / 0.1, 1) # Cap at 0.1s
                                        w_state.access_frequencies.append(freq)
                                    
                                    p_state.last_write_time = parsed_time
                                    p_state.last_write_file = file_accessed

                                elif major_op in self.actions['FILE_RENAME_MOVED']:
                                    w_state.delete_count += 1

                                # --- Check Time Window ---
                                if self._date_diff_in_seconds(current_time[pid], previous_time[pid]) >= self.time_window:
                                    # Only save if there was actual activity relevant to features
                                    # (e.g. at least 1 write, delete, or rename)
                                    if w_state.entropy_ratios or w_state.delete_count > 0:
                                        vec = self._calculate_window_vector(w_state)
                                        global_features.append(vec + ['N']) # Label Benign

                                    # Reset Window State
                                    previous_time[pid] = current_time[pid]
                                    w_states[pid] = WindowState()

                    except Exception: pass

                # Flush per session
                if global_features:
                    with open(output_file, 'a', newline='') as f:
                        csv.writer(f).writerows(global_features)
                    global_features = []
                print(f"    Finished session {session_name}")

    def extract_ransomware_features(self):
        output_file = FEATURES_PATH / f"ransomware_redemption_features_{self.time_window}sec.csv"
        logs_path = LOGS_PATH / "ransomware-irp-logs"
        
        global_features = []

        for session_name in os.listdir(logs_path):
            session_path = logs_path / session_name
            if not session_path.is_file() or not session_name.endswith('.gz'): continue

            print(f"Processing ransomware session: {session_name}")
            target_pid = self.session_pid_map.get(session_name)
            
            p_states = defaultdict(PersistentState)
            w_states = defaultdict(WindowState)
            previous_time = {}
            current_time = {}

            try:
                with gzip.open(session_path, 'rt', encoding='utf-8', errors='ignore') as fin:
                    next(fin); next(fin) # Skip headers

                    for line in fin:
                        line = line.strip().split('\t')
                        if len(line) != 23: continue

                        major_op = line[7].strip()
                        pid = line[4].split('.')[0].strip()
                        post_time = self._rreplace(line[3].strip(), ':', '.')
                        
                        if target_pid and pid != target_pid: continue

                        parsed_time = datetime.strptime(post_time, '%H:%M:%S.%f')
                        file_accessed = line[22].strip().lower()

                        if file_accessed in ('0.000000000000000', 'cannot get name', ''): continue

                        if pid not in previous_time:
                            previous_time[pid] = parsed_time
                        current_time[pid] = parsed_time

                        p_state = p_states[pid]
                        w_state = w_states[pid]

                        try:
                            offset_hex = line[14].strip()
                            offset = int(offset_hex, 16) if offset_hex.startswith('0x') else int(offset_hex)
                        except: offset = 0

                        if major_op in self.actions['FILE_READ']:
                            ent = self._safe_float(line[21])
                            if ent is not None:
                                p_state.read_history[file_accessed][offset] = ent
                        
                        elif major_op in self.actions['FILE_WRITE']:
                            ent = self._safe_float(line[21])
                            
                            prev_read = p_state.read_history.get(file_accessed, {}).get(offset)
                            ratio = 0.0
                            if prev_read and ent and ent > prev_read:
                                ratio = 1.0 - (prev_read / ent)
                            w_state.entropy_ratios.append(ratio)
                            
                            dpath, fname = os.path.split(file_accessed.replace("\\", "/"))
                            w_state.dir_writes[dpath].add(fname)
                            w_state.file_classes.add(self._get_file_class(file_accessed))

                            if p_state.last_write_time and p_state.last_write_file != file_accessed:
                                delta = self._date_diff_in_seconds(parsed_time, p_state.last_write_time)
                                freq = 1 - min(delta / 0.1, 1)
                                w_state.access_frequencies.append(freq)
                            
                            p_state.last_write_time = parsed_time
                            p_state.last_write_file = file_accessed

                        elif major_op in self.actions['FILE_RENAME_MOVED']:
                            w_state.delete_count += 1

                        # Check Window
                        if self._date_diff_in_seconds(current_time[pid], previous_time[pid]) >= self.time_window:
                            if w_state.entropy_ratios or w_state.delete_count > 0:
                                vec = self._calculate_window_vector(w_state)
                                global_features.append(vec + ['M']) # Label Malicious
                            
                            previous_time[pid] = current_time[pid]
                            w_states[pid] = WindowState()

            except Exception as e:
                print(f"Error processing {session_name}: {e}")

            if global_features:
                with open(output_file, 'a', newline='') as f:
                    csv.writer(f).writerows(global_features)
                global_features = []

    def train_model(self, model_name):
        benign_path = FEATURES_PATH / f"benign_redemption_features_{self.time_window}sec.csv"
        ransom_path = FEATURES_PATH / f"ransomware_redemption_features_{self.time_window}sec.csv"

        def load_data(path):
            X, y = [], []
            if not path.exists(): return np.array(X), np.array(y)
            print(f"    📂 Loading features from: {path.name}")
            with open(path, 'r') as f:
                reader = csv.reader(f)
                for row in reader:
                    try:
                        # columns 0-5 are features, 6 is label
                        X.append([float(x) for x in row[:6]])
                        y.append(row[6])
                    except: pass
            return np.array(X), np.array(y)

        benign_x, benign_y = load_data(benign_path)
        ransom_x, ransom_y = load_data(ransom_path)

        if len(benign_x) == 0 or len(ransom_x) == 0:
            print("    ❌ Not enough data to train.")
            return

        X = np.concatenate((benign_x, ransom_x))
        y = np.concatenate((benign_y, ransom_y))
        print(f"    ⬆ Loaded {len(X)} total samples.")

        train_x, test_x, train_y, test_y = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
        
        print(f"    Training '{model_name}' model...")
        model_class = MODEL_REGISTRY[model_name]
        # Pass empty dict for params or load from config if needed
        model = model_class() 
        model.train(train_x, train_y)
        
        save_path = SAVED_MODELS_PATH / f"{calculate_hash('Redemption', model_name)}.pkl"
        model.save(save_path)
        print(f"    ✅ Model saved to {save_path}")

    def evaluate(self, model_name, saved_model):
        results_file = RESULTS_PATH / "evaluation_results.csv"
        benign_path = FEATURES_PATH / f"benign_redemption_features_{self.time_window}sec.csv"
        ransom_path = FEATURES_PATH / f"ransomware_redemption_features_{self.time_window}sec.csv"

        def load_data(path):
            X, y = [], []
            if not path.exists(): return np.array(X), np.array(y)
            print(f"    📂 Loading features from: {path.name}")
            with open(path, 'r') as f:
                reader = csv.reader(f)
                for row in reader:
                    try:
                        X.append([float(x) for x in row[:6]])
                        y.append(row[6])
                    except: pass
            return np.array(X), np.array(y)

        benign_x, benign_y = load_data(benign_path)
        ransom_x, ransom_y = load_data(ransom_path)
        
        if len(benign_x) == 0 and len(ransom_x) == 0:
            print("    ❌ No data found.")
            return

        X = np.concatenate((benign_x, ransom_x))
        y = np.concatenate((benign_y, ransom_y))

        _, test_x, _, test_y = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

        model_path = SAVED_MODELS_PATH / saved_model
        if not model_path.exists():
            print(f"    ❌ Model not found: {model_path}")
            return
        
        model = joblib.load(model_path)
        print(f"    ✅ Loaded model from {model_path}")

        predictions = model.predict(test_x)

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

        cm = metrics.confusion_matrix(test_y, predictions)
        print("\n🔍 Confusion Matrix:")
        print(cm)
        
        roc_auc = ""
        if len(set(test_y)) == 2:
            try:
                y_prob = model.predict_proba(test_x)[:, 1]
                roc_auc = metrics.roc_auc_score(test_y, y_prob)
                print(f"\n🏅 ROC AUC: {roc_auc:.4f}")
            except: pass

        os.makedirs(RESULTS_PATH, exist_ok=True)
        file_exists = results_file.exists()
        with open(results_file, "a", newline="") as fp:
            writer = csv.writer(fp)
            if not file_exists:
                writer.writerow(["Model", "Model Hash", "Accuracy", "Precision", "Recall", "F1_score", "ROC_AUC", "Confusion_Matrix"])
            
            writer.writerow([
                model_name, saved_model, 
                f"{accuracy:.4f}", f"{precision:.4f}", f"{recall:.4f}", f"{f1:.4f}", 
                f"{roc_auc:.4f}" if roc_auc != "" else "", cm.tolist()
            ])
        print(f"\n    💾 Results saved to {results_file}")

    def evaluate_attack(self, model_name, saved_model):
        results_file = RESULTS_PATH / "evaluation_results.csv"
        
        # --- CONFIGURATION: Point this to your ATTACK file ---
        attack_path = ATTACKS_PATH / "process_splitting_Redemption_10" / "ransomware_redemption_features_5sec.csv"
        

        def load_data(path):
            X, y = [], []
            if not path.exists(): return np.array(X), np.array(y)
            print(f"    📂 Loading features from: {path.name}")
            with open(path, 'r') as f:
                reader = csv.reader(f)
                for row in reader:
                    try:
                        X.append([float(x) for x in row[:6]])
                        y.append(row[6])
                    except: pass
            return np.array(X), np.array(y)

        # --- 2. LOAD ONLY ATTACK DATA ---  
        print(f"    ⚔️  Loading Attack Data...")
        test_x, test_y = load_data(attack_path)
        
        if len(test_x) == 0:
            print(f"    ❌ No data found at {attack_path}")
            return

        # --- 3. NO SPLITTING ---
        print(f"    📊 Testing on {len(test_x)} samples (100% of generated attack vectors)")

        model_path = SAVED_MODELS_PATH / saved_model
        if not model_path.exists():
            print(f"    ❌ Model not found: {model_path}")
            return
        
        model = joblib.load(model_path)
        print(f"    ✅ Loaded model from {model_path}")

        predictions = model.predict(test_x)

        # Metrics
        accuracy = metrics.accuracy_score(test_y, predictions)
        # Note: Precision/F1 might warn if only one class (M) is present, which is expected in attack tests.
        precision = metrics.precision_score(test_y, predictions, average='weighted', zero_division=0)
        recall = metrics.recall_score(test_y, predictions, average='weighted', zero_division=0)
        f1 = metrics.f1_score(test_y, predictions, average='weighted', zero_division=0)

        print("\n📈 Performance Metrics:")
        print(f"    Accuracy : {accuracy:.4f}")
        print(f"    Precision: {precision:.4f}")
        print(f"    Recall   : {recall:.4f}")
        print(f"    F1-score : {f1:.4f}")

        print("\n📄 Classification Report:")
        print(metrics.classification_report(test_y, predictions, zero_division=0))

        cm = metrics.confusion_matrix(test_y, predictions)
        print("\n🔍 Confusion Matrix:")
        print(cm)
        
        # ROC AUC requires 2 classes. If testing ONLY malware, this will skip.
        roc_auc = ""
        if len(set(test_y)) == 2:
            try:
                y_prob = model.predict_proba(test_x)[:, 1]
                roc_auc = metrics.roc_auc_score(test_y, y_prob)
                print(f"\n🏅 ROC AUC: {roc_auc:.4f}")
            except: pass
        else:
            print("\n🏅 ROC AUC: N/A (Only one class present in test set)")

        # Save Results
        os.makedirs(RESULTS_PATH, exist_ok=True)
        file_exists = results_file.exists()
        with open(results_file, "a", newline="") as fp:
            writer = csv.writer(fp)
            if not file_exists:
                writer.writerow(["Model", "Model Hash", "Accuracy", "Precision", "Recall", "F1_score", "ROC_AUC", "Confusion_Matrix"])
            
            writer.writerow([
                model_name, saved_model, 
                f"{accuracy:.4f}", f"{precision:.4f}", f"{recall:.4f}", f"{f1:.4f}", 
                f"{roc_auc:.4f}" if roc_auc != "" else "N/A", cm.tolist()
            ])
        print(f"\n    💾 Results saved to {results_file}")