from collections import defaultdict, Counter
import numpy as np
from sklearn import metrics
from sklearn.model_selection import train_test_split
from models import MODEL_REGISTRY
import os
import gzip
import csv
import joblib
from datetime import datetime
from scripts.utils.load_config import config, BASE_DIR
from scripts.utils.calculate_hash import calculate_hash

TIME_WINDOW = config['CanCal']['time_window'] 
LOGS_PATH = BASE_DIR / 'data' / 'ShieldFS-dataset' 
FEATURES_PATH = BASE_DIR / 'datasets' / 'CanCal'
SAVED_MODELS_PATH = BASE_DIR / 'saved_models'
RESULTS_PATH = BASE_DIR / 'results' / 'CanCal'

# --- GLOBAL CONSTANTS ---
FILE_RENAME_CODE = '0x000000000000000A' 
FILE_DELETE_CODE = '0x000000000000000D' 

ACTIONS = {
    'FILE_CREATE': ['IRP_MJ_CREATE'],  
    'FILE_SET_INFO': ['IRP_MJ_SET_INFORMATION'], 
}

SESSION_PID_MAP = {
    '480bd1ecb1b969e6677c1e11a30cd985e4244e5de04956e2dbb0e6b97c42027e.gz': '2616',
    '09c278fc0ae3a36170a71e65bba9f92da086fca941ba93051811bf16c6b67f64.gz': '2060',
    '0d6fb25cde440df0d2b6a676e86b23c47c298f60f8ec461805cc4cd77dd9f730.gz': '3680',
    'c80d611b38c6ea23cf9d564111a24f245f48df48a5341da896912054dd7d9529.gz': '3684'
}

class CanCal:
    def __init__(self):
        self.time_window = TIME_WINDOW
        self.actions = ACTIONS
        self.session_pid_map = SESSION_PID_MAP
        
        # Complete Feature List (9 Features)
        self.tracking_features = [
            'n_create', 'n_delete', 'n_renamed', # Coarse-grained
            'rtype', 'rtype_change',             # Fusion-based (Types)
            'max_n_file', 'n_folder', 'r_file',  # Fusion-based (Ransom Note)
            'ntype_change'                       # Encryption Mode
        ]

    @staticmethod
    def date_diff_in_seconds(dt2, dt1):
        return (dt2 - dt1).total_seconds()
    
    @staticmethod
    def rreplace(s, old, new):
        return (s[::-1].replace(old[::-1], new[::-1], 1))[::-1]

    @staticmethod
    def load_csv_features(path, feature_cols=[0,1,2,3,4,5,6,7,8], label_col=9):
        X, y = [], []
        print(f"    📂 Loading features from: {path}")
        with open(path) as f:
            reader = csv.reader(f)
            header = next(reader, None) 
            for i, row in enumerate(reader, 1):
                try:
                    features = [float(row[i]) for i in feature_cols]
                    label = row[label_col]
                    X.append(features)
                    y.append(label)
                except Exception as e:
                    print(f"Row {i} in {path} is malformed: {e}")
        return np.array(X), np.array(y)
   
    @staticmethod
    def get_file_details(file_path):
        """Extracts extension, filename, and parent folder from path."""
        try:
            if not file_path or file_path.strip() == '':
                return None, None, None
            
            # Extract extension
            _, ext = os.path.splitext(file_path)
            ext = ext.lower() if ext else None

            path_fixed = file_path.replace('\\', '/')
            folder, filename = os.path.split(path_fixed)
            
            return ext, filename, folder
        except:
            return None, None, None

    def process_session(self, session_path, target_pid=None, label='N'):
        """Helper to process a single session file and return feature vectors."""
        
        # 1. Window Counters (Reset every window)
        features = defaultdict(lambda: {k: 0 for k in self.tracking_features})
        
        # 2. Window Specific State (Sets/Counters that reset every window)
        #    - created_exts/deleted_exts: For rtype_change
        #    - filename_counts: For max_n_file (Counts creates of specific filenames)
        #    - filename_folders: For n_folder (Tracks which folders a filename appears in)
        window_state = defaultdict(lambda: {
            'created_exts': set(), 
            'deleted_exts': set(),
            'filename_counts': Counter(),
            'filename_folders': defaultdict(set)
        })

        # 3. Persistent State (Lifetime of PID)
        #    - extensions: Set of all extensions seen ever
        #    - ntype_start: Count of extensions at start of current window
        persistent_state = defaultdict(lambda: {'extensions': set(), 'ntype_start': 0})
        
        previous_time = {}
        current_time = {}
        global_features = []

        try:
            with gzip.open(session_path, 'rt', encoding='utf-8', errors='ignore') as fin:
                # Skip header if ransomware logs (heuristic based on your snippet)
                if label == 'M':
                    next(fin); next(fin) 

                start_index = 3 if label == 'M' else 1
                
                for line_num, line in enumerate(fin, start_index):
                    line = line.strip().split('\t')
                    if len(line) != 23: continue

                    try:
                        major_op = line[7].strip()
                        process_pid = line[4].split('.')[0].strip()
                        post_time = self.rreplace(line[3].strip(), ':', '.')
                        
                        # Filter for target PID if extracting ransomware
                        if target_pid and process_pid != target_pid:
                            continue

                        parsed_time = datetime.strptime(post_time, '%H:%M:%S.%f')
                        param_code = line[15].strip()
                        file_full_path = line[22].strip()
                        
                    except Exception:
                        continue

                    # Initialize PID state
                    if process_pid not in previous_time:
                        previous_time[process_pid] = parsed_time
                        # Snapshot ntype at start (0 for new process)
                        persistent_state[process_pid]['ntype_start'] = 0

                    current_time[process_pid] = parsed_time
                    
                    # Parse File Details
                    ext, filename, folder = self.get_file_details(file_full_path)

                    # --- CORE LOGIC ---
                    if major_op == 'IRP_MJ_SET_INFORMATION':
                        if param_code == FILE_RENAME_CODE:
                            features[process_pid]['n_renamed'] += 1
                            if ext: persistent_state[process_pid]['extensions'].add(ext)

                        elif param_code == FILE_DELETE_CODE:
                            features[process_pid]['n_delete'] += 1
                            if ext: 
                                persistent_state[process_pid]['extensions'].add(ext)
                                window_state[process_pid]['deleted_exts'].add(ext)

                    elif major_op == 'IRP_MJ_CREATE':
                        features[process_pid]['n_create'] += 1
                        if ext: 
                            persistent_state[process_pid]['extensions'].add(ext)
                            window_state[process_pid]['created_exts'].add(ext)
                        
                        # Track for Ransom Note Features (Def 6, 7, 8)
                        # "Number of created files with the same name" 
                        if filename:
                            window_state[process_pid]['filename_counts'][filename] += 1
                            window_state[process_pid]['filename_folders'][filename].add(folder)
                    
                    # --- TIME WINDOW CHECK ---
                    if self.date_diff_in_seconds(current_time[process_pid], previous_time[process_pid]) >= self.time_window:
                        counts = features[process_pid]
                        p_state = persistent_state[process_pid]
                        w_state = window_state[process_pid]

                        # 1. Feature: rtype [cite: 480]
                        # Ratio of types AFTER / types BEFORE
                        ntype_start = p_state['ntype_start']
                        ntype_end = len(p_state['extensions'])
                        denom_rtype = ntype_start if ntype_start > 0 else 1
                        counts['rtype'] = ntype_end / denom_rtype

                        # 2. Feature: rtype_change [cite: 485]
                        # Ratio of types DELETED / types CREATED (in this window)
                        ntype_del_w = len(w_state['deleted_exts'])
                        ntype_create_w = len(w_state['created_exts'])
                        denom_change = ntype_create_w if ntype_create_w > 0 else 1
                        counts['rtype_change'] = ntype_del_w / denom_change

                        # 3. Feature: ntype_change [cite: 473]
                        # Net change in types count
                        counts['ntype_change'] = ntype_end - ntype_start

                        # 4. Ransom Note Features: max_n_file, n_folder, r_file [cite: 487-493]
                        if w_state['filename_counts']:
                            # Find the filename created most often
                            most_common_file, max_count = w_state['filename_counts'].most_common(1)[0]
                            
                            # How many folders was it created in?
                            folder_count = len(w_state['filename_folders'][most_common_file])
                            folder_count = folder_count if folder_count > 0 else 1
                            
                            counts['max_n_file'] = max_count
                            counts['n_folder'] = folder_count
                            counts['r_file'] = max_count / folder_count
                        else:
                            counts['max_n_file'] = 0
                            counts['n_folder'] = 0
                            counts['r_file'] = 0

                        # Extract Vector
                        feature_vector = [counts.get(k, 0) for k in self.tracking_features]
                        
                        # Only save if there was some activity
                        if any(feature_vector):
                            global_features.append(feature_vector + [label]) 
                            
                        # Reset for Next Window
                        previous_time[process_pid] = current_time[process_pid]
                        p_state['ntype_start'] = ntype_end # Update start baseline
                        
                        # Clear Window State
                        for k in self.tracking_features: counts[k] = 0
                        w_state['created_exts'].clear()
                        w_state['deleted_exts'].clear()
                        w_state['filename_counts'].clear()
                        w_state['filename_folders'].clear()

        except Exception as e:
            print(f"Error processing {session_path}: {e}")

        return global_features

    def extract_benign_features(self):
        output_file = FEATURES_PATH / f"benign_cancal_features_{self.time_window}sec.csv"
        benign_logs_path = LOGS_PATH / "benign-irp-logs"
        
        if not output_file.exists():
            header = self.tracking_features + ['Label']
            with open(output_file, 'w', newline='') as f:
                csv.writer(f).writerow(header)

        for machine_name in os.listdir(benign_logs_path):
            machine_path = benign_logs_path / machine_name
            if not machine_path.is_dir(): continue
            print(f"Processing machine: {machine_name}")

            for session_name in os.listdir(machine_path):
                session_folder = machine_path / session_name
                if not session_folder.is_dir(): continue
                print(f"Processing session: {session_name}")

                for in_file in os.listdir(session_folder):
                    if in_file.endswith('.gz'):
                        features = self.process_session(session_folder / in_file, label='N')
                        if features:
                            with open(output_file, 'a', newline='') as f:
                                csv.writer(f).writerows(features)

    def extract_ransomware_features(self):
        logs_path = LOGS_PATH / "ransomware-irp-logs"
        output_file = FEATURES_PATH / f"ransomware_cancal_features_{self.time_window}sec.csv"
        
        if not output_file.exists():
            header = self.tracking_features + ['Label']
            with open(output_file, 'w', newline='') as f:
                csv.writer(f).writerow(header)

        for session_name in os.listdir(logs_path):
            if not session_name.endswith('.gz'): continue
            
            print(f"Processing ransomware session: {session_name}")
            target_pid = self.session_pid_map.get(session_name)
            
            features = self.process_session(logs_path / session_name, target_pid=target_pid, label='M')
            
            if features:
                with open(output_file, 'a', newline='') as f:
                    csv.writer(f).writerows(features)
            print(f"Finished session {session_name}")

    def train_model(self, model_name):
        benign_features_path = FEATURES_PATH / f"benign_cancal_features_{self.time_window}sec.csv"
        ransomware_features_path = FEATURES_PATH / f"ransomware_cancal_features_{self.time_window}sec.csv"

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
        model_params = config["CanCal"].get(model_name, {})
        model_class = MODEL_REGISTRY[model_name]
        model = model_class(**model_params)
        
        print(f"    Training '{model_name}' model...")
        model.train(train_x, train_y)
        print(f"    ✅ Model training completed")

        #  Save model 
        model_path = SAVED_MODELS_PATH / f"{calculate_hash('CanCal', model_name)}.pkl"
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        model.save(model_path)

    def evaluate(self, model_name, saved_model):
        # Path to results
        results_file = RESULTS_PATH / "evaluation_results.csv"
        
        # Paths to features
        benign_features_path = FEATURES_PATH / f"benign_cancal_features_{self.time_window}sec.csv"
        ransomware_features_path = FEATURES_PATH / f"ransomware_cancal_features_{self.time_window}sec.csv"

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
            
