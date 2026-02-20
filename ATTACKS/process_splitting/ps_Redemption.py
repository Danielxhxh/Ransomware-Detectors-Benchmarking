import os
import gzip
import csv
import sys
import json
from collections import defaultdict
from datetime import datetime
from typing import List, Set, Optional
from dataclasses import dataclass, field

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from scripts.utils.load_config import config, BASE_DIR

# --- CONFIGURATION ---
N_SPLITS = 10 

TIME_WINDOW = config['Redemption']['time_window'] 
FEATURES_PATH = BASE_DIR / 'ATTACKS' 
LOGS_PATH = BASE_DIR / 'data' / 'ShieldFS-dataset'

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

SESSION_PID_MAP = json.loads((LOGS_PATH / 'ransomware-pids.json').read_text()) if (LOGS_PATH / 'ransomware-pids.json').exists() else {}

# --- DATA CLASSES (Same as Redemption.py) ---
@dataclass
class PersistentState:
    read_history: dict = field(default_factory=lambda: defaultdict(dict))
    last_write_time: Optional[datetime] = None
    last_write_file: str = ""

@dataclass
class WindowState:
    entropy_ratios: List[float] = field(default_factory=list)
    modified_blocks: Set[str] = field(default_factory=set)
    delete_count: int = 0
    dir_writes: dict = field(default_factory=lambda: defaultdict(set))
    file_classes: Set[str] = field(default_factory=set)
    access_frequencies: List[float] = field(default_factory=list)

# --- HELPER FUNCTIONS ---
def _get_file_class(filename):
    _, ext = os.path.splitext(filename.lower())
    return EXTENSION_LOOKUP.get(ext, "other")

def _date_diff_in_seconds(dt2, dt1) -> float:
    return (dt2 - dt1).total_seconds()

def _rreplace(s, old, new):
    return (s[::-1].replace(old[::-1], new[::-1], 1))[::-1]

def _safe_float(value: str) -> Optional[float]:
    try:
        return float(value.strip())
    except ValueError:
        return None

def _calculate_window_vector(w_state: WindowState) -> List[float]:
    # r1: Entropy Ratio
    r1 = sum(w_state.entropy_ratios) / len(w_state.entropy_ratios) if w_state.entropy_ratios else 0.0
    # r2: Modified Blocks (Raw Count)
    r2 = float(len(w_state.modified_blocks))
    # r3: Delete Count (Boolean logic for vector)
    r3 = 1.0 if w_state.delete_count > 0 else 0.0
    # r4: Directory Traversal
    max_traversal = 0.0
    for dir_path, files in w_state.dir_writes.items():
        val = min(len(files) / 50.0, 1.0)
        if val > max_traversal: max_traversal = val
    r4 = max_traversal
    # r5: File Type Changes
    r5 = 1.0 if len(w_state.file_classes) > 1 else 0.0
    # r6: Frequency
    r6 = sum(w_state.access_frequencies) / len(w_state.access_frequencies) if w_state.access_frequencies else 0.0
    
    return [r1, r2, r3, r4, r5, r6]

def extract_split_redemption_features():
    output_base_path = FEATURES_PATH / f"process_splitting_Redemption_{N_SPLITS}"
    ransomware_logs_path = LOGS_PATH / "ransomware-irp-logs"
    
    output_file = output_base_path / f"ransomware_redemption_features_{TIME_WINDOW}sec.csv"
    
    print(f"[*] Starting Redemption Process Splitting (N={N_SPLITS})")
    print(f"[*] Time Window: {TIME_WINDOW} seconds")
    print(f"[*] Saving to: {output_file}")

    os.makedirs(output_base_path, exist_ok=True)
    
    # Initialize output file
    with open(output_file, 'w', newline='') as f:
        pass 

    for session_name in os.listdir(ransomware_logs_path):
        session_path = ransomware_logs_path / session_name
        
        if not session_name.endswith(".gz") or session_name not in SESSION_PID_MAP:
            continue

        print(f" -> Processing session: {session_name}")
        target_pid = SESSION_PID_MAP.get(session_name)

        # --- INITIALIZE SPLIT STATES ---
        # Each split index (0 to N-1) behaves like an independent process
        split_p_states = [PersistentState() for _ in range(N_SPLITS)]
        split_w_states = [WindowState() for _ in range(N_SPLITS)]
        
        # Each split needs its own clock
        split_prev_time = [None] * N_SPLITS
        split_curr_time = [None] * N_SPLITS
        
        op_counter = 0 # Round Robin Counter
        global_features = []

        try:
            with gzip.open(session_path, 'rt', encoding='utf-8', errors='ignore') as fin:
                next(fin); next(fin) # Skip headers

                for line in fin:
                    line = line.strip().split('\t')
                    if len(line) != 23: continue

                    major_op = line[7].strip()
                    pid = line[4].split('.')[0].strip()
                    post_time = _rreplace(line[3].strip(), ':', '.')
                    
                    if pid != target_pid: continue

                    parsed_time = datetime.strptime(post_time, '%H:%M:%S.%f')
                    file_accessed = line[22].strip().lower()

                    if file_accessed in ('0.000000000000000', 'cannot get name', ''): continue

                    # --- ROUND ROBIN DISTRIBUTION ---
                    split_idx = op_counter % N_SPLITS
                    op_counter += 1
                    
                    # Get State for THIS Split
                    p_state = split_p_states[split_idx]
                    w_state = split_w_states[split_idx]
                    
                    # Update Time for THIS Split
                    if split_prev_time[split_idx] is None:
                        split_prev_time[split_idx] = parsed_time
                    split_curr_time[split_idx] = parsed_time
                    
                    # --- FEATURE UPDATE ---
                    try:
                        offset_hex = line[14].strip()
                        offset = int(offset_hex, 16) if offset_hex.startswith('0x') else int(offset_hex)
                    except: offset = 0

                    if major_op in ACTIONS['FILE_READ']:
                        ent = _safe_float(line[21])
                        if ent is not None:
                            p_state.read_history[file_accessed][offset] = ent
                    
                    elif major_op in ACTIONS['FILE_WRITE']:
                        ent = _safe_float(line[21])
                        
                        # r1: Entropy Ratio
                        # Note: If Split A read it, but Split B writes it, prev_read will be None.
                        # This naturally lowers r1 (Evasion success).
                        prev_read = p_state.read_history.get(file_accessed, {}).get(offset)
                        ratio = 0.0
                        if prev_read and ent and ent > prev_read:
                            ratio = 1.0 - (prev_read / ent)
                        w_state.entropy_ratios.append(ratio)
                        
                        # r2: Modified Blocks (Approx)
                        block_id = f"{file_accessed}|{offset // 4096}"
                        w_state.modified_blocks.add(block_id)

                        # r4: Dir Traversal
                        dpath, fname = os.path.split(file_accessed.replace("\\", "/"))
                        w_state.dir_writes[dpath].add(fname)
                        
                        # r5: Ext
                        w_state.file_classes.add(_get_file_class(file_accessed))

                        # r6: Frequency
                        if p_state.last_write_time and p_state.last_write_file != file_accessed:
                            delta = _date_diff_in_seconds(parsed_time, p_state.last_write_time)
                            freq = 1 - min(delta / 0.1, 1)
                            w_state.access_frequencies.append(freq)
                        
                        p_state.last_write_time = parsed_time
                        p_state.last_write_file = file_accessed

                    elif major_op in ACTIONS['FILE_RENAME_MOVED']:
                        w_state.delete_count += 1

                    # --- CHECK TIME WINDOW (For This Split) ---
                    if _date_diff_in_seconds(split_curr_time[split_idx], split_prev_time[split_idx]) >= TIME_WINDOW:
                        # Only save if there was actual activity
                        if w_state.entropy_ratios or w_state.delete_count > 0:
                            vec = _calculate_window_vector(w_state)
                            global_features.append(vec + ['M'])
                        
                        # Reset THIS split's window
                        split_prev_time[split_idx] = split_curr_time[split_idx]
                        split_w_states[split_idx] = WindowState()

        except Exception as e:
            print(f"Error processing {session_name}: {e}")

        # Save session results
        if global_features:
            with open(output_file, 'a', newline='') as f:
                csv.writer(f).writerows(global_features)
            print(f"    -> Generated {len(global_features)} vectors.")

if __name__ == "__main__":
    if not os.path.exists(LOGS_PATH):
        print(f"[!] Error: Log path not found: {LOGS_PATH}")
    else:
        extract_split_redemption_features()
        print("\n[+] Redemption Process Splitting complete.")