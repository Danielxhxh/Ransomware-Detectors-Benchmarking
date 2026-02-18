import os
import gzip
import csv
import sys
from collections import defaultdict
from datetime import datetime
from typing import List, Set, Optional
from dataclasses import dataclass, field

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from scripts.utils.load_config import config, BASE_DIR

# --- CONFIGURATION ---
N_SUB_SPLITS = 5

TIME_WINDOW = config['Redemption']['time_window'] 
FEATURES_PATH = BASE_DIR / 'ATTACKS' 
LOGS_PATH = BASE_DIR / 'data' / 'ShieldFS-dataset'

FILE_RENAME_CODE = '0x000000000000000A' 
FILE_DELETE_CODE = '0x000000000000000D' 

SESSION_PID_MAP = {
    '480bd1ecb1b969e6677c1e11a30cd985e4244e5de04956e2dbb0e6b97c42027e.gz': '2616',
    '09c278fc0ae3a36170a71e65bba9f92da086fca941ba93051811bf16c6b67f64.gz': '2060',
    '0d6fb25cde440df0d2b6a676e86b23c47c298f60f8ec461805cc4cd77dd9f730.gz': '3680',
    'c80d611b38c6ea23cf9d564111a24f245f48df48a5341da896912054dd7d9529.gz': '3684'
}

# --- EXTENSION LOOKUPS & DATA CLASSES (Copied from Redemption.py) ---
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

def _get_file_class(filename):
    _, ext = os.path.splitext(filename.lower())
    return EXTENSION_LOOKUP.get(ext, "other")

def _date_diff_in_seconds(dt2, dt1) -> float:
    return (dt2 - dt1).total_seconds()

def _rreplace(s, old, new):
    return (s[::-1].replace(old[::-1], new[::-1], 1))[::-1]

def _safe_float(value: str) -> Optional[float]:
    try: return float(value.strip())
    except: return None

def _calculate_window_vector(w_state: WindowState) -> List[float]:
    r1 = sum(w_state.entropy_ratios) / len(w_state.entropy_ratios) if w_state.entropy_ratios else 0.0
    r2 = float(len(w_state.modified_blocks))
    r3 = 1.0 if w_state.delete_count > 0 else 0.0
    
    max_traversal = 0.0
    for dir_path, files in w_state.dir_writes.items():
        val = min(len(files) / 50.0, 1.0)
        if val > max_traversal: max_traversal = val
    r4 = max_traversal
    
    r5 = 1.0 if len(w_state.file_classes) > 1 else 0.0
    r6 = sum(w_state.access_frequencies) / len(w_state.access_frequencies) if w_state.access_frequencies else 0.0
    
    return [r1, r2, r3, r4, r5, r6]

def extract_functional_split_redemption_features():
    output_base_path = FEATURES_PATH / f"functional_splitting"
    ransomware_logs_path = LOGS_PATH / "ransomware-irp-logs"
    
    output_file = output_base_path / f"ransomware_redemption_features_{TIME_WINDOW}sec.csv"
    
    print(f"[*] Starting Redemption Functional Splitting (N_SUB={N_SUB_SPLITS})")
    print(f"[*] Functional Groups: READ, WRITE, DELETE")
    
    os.makedirs(output_base_path, exist_ok=True)
    with open(output_file, 'w', newline='') as f: pass 

    for session_name in os.listdir(ransomware_logs_path):
        session_path = ransomware_logs_path / session_name
        
        if not session_name.endswith(".gz") or session_name not in SESSION_PID_MAP: continue

        print(f" -> Processing session: {session_name}")
        ransomware_pid = SESSION_PID_MAP.get(session_name)

        # --- FUNCTIONAL GROUPS ---
        # We need groups for: READ, WRITE, DELETE
        # RENAME is usually the encryption step (Write+Delete), so we treat it as WRITE behavior or DELETE behavior depending on implementation.
        # Here we map:
        # READ -> READ Group
        # WRITE -> WRITE Group
        # RENAME/DELETE -> DELETE Group (or RENAME Group)
        
        functional_groups = {
            'READ':  ([PersistentState() for _ in range(N_SUB_SPLITS)], 
                      [WindowState() for _ in range(N_SUB_SPLITS)],
                      [None]*N_SUB_SPLITS, [None]*N_SUB_SPLITS), # p_states, w_states, prev_time, curr_time
            'WRITE': ([PersistentState() for _ in range(N_SUB_SPLITS)], 
                      [WindowState() for _ in range(N_SUB_SPLITS)],
                      [None]*N_SUB_SPLITS, [None]*N_SUB_SPLITS),
            'DELETE':([PersistentState() for _ in range(N_SUB_SPLITS)], 
                      [WindowState() for _ in range(N_SUB_SPLITS)],
                      [None]*N_SUB_SPLITS, [None]*N_SUB_SPLITS)
        }
        
        group_counters = defaultdict(int)
        global_features = []

        try:
            with gzip.open(session_path, 'rt', encoding='utf-8', errors='ignore') as fin:
                next(fin); next(fin)

                for line in fin:
                    line = line.strip().split('\t')
                    if len(line) != 23: continue

                    major_op = line[7].strip()
                    pid = line[4].split('.')[0].strip()
                    post_time = _rreplace(line[3].strip(), ':', '.')
                    
                    if pid != ransomware_pid: continue

                    parsed_time = datetime.strptime(post_time, '%H:%M:%S.%f')
                    file_accessed = line[22].strip().lower()
                    param_code = line[15].strip()
                    
                    if file_accessed in ('0.000000000000000', 'cannot get name', ''): continue

                    # 1. Determine Target Group
                    target_group = None
                    if major_op == 'IRP_MJ_READ':
                        target_group = 'READ'
                    elif major_op == 'IRP_MJ_WRITE':
                        target_group = 'WRITE'
                    elif major_op == 'IRP_MJ_SET_INFORMATION': # Rename/Delete
                        target_group = 'DELETE' # Simplified for Redemption: Deletes are the suspicious part
                    
                    if not target_group: continue

                    # 2. Select Sub-Process
                    idx = group_counters[target_group] % N_SUB_SPLITS
                    group_counters[target_group] += 1
                    
                    p_states, w_states, prev_times, curr_times = functional_groups[target_group]
                    
                    p_state = p_states[idx]
                    w_state = w_states[idx]
                    
                    # Time Management
                    if prev_times[idx] is None: prev_times[idx] = parsed_time
                    curr_times[idx] = parsed_time
                    
                    # 3. Update State
                    try:
                        offset_hex = line[14].strip()
                        offset = int(offset_hex, 16) if offset_hex.startswith('0x') else int(offset_hex)
                    except: offset = 0

                    if target_group == 'READ':
                        ent = _safe_float(line[21])
                        if ent is not None:
                            p_state.read_history[file_accessed][offset] = ent
                            # Readers ONLY Read. No R1, R2, R3 updates.
                            
                    elif target_group == 'WRITE':
                        ent = _safe_float(line[21])
                        
                        # R1: Entropy Ratio
                        # CRITICAL: This WRITE process has NO read_history (it's in the READ group).
                        # So prev_read will always be None -> R1 = 0.0
                        prev_read = p_state.read_history.get(file_accessed, {}).get(offset) 
                        ratio = 0.0
                        if prev_read and ent and ent > prev_read:
                            ratio = 1.0 - (prev_read / ent)
                        w_state.entropy_ratios.append(ratio)

                        # R2: Modified Blocks
                        w_state.modified_blocks.add(f"{file_accessed}|{offset // 4096}")
                        
                        # R4, R5
                        dpath, fname = os.path.split(file_accessed.replace("\\", "/"))
                        w_state.dir_writes[dpath].add(fname)
                        w_state.file_classes.add(_get_file_class(file_accessed))
                        
                        # R6: Frequency
                        if p_state.last_write_time and p_state.last_write_file != file_accessed:
                            delta = _date_diff_in_seconds(parsed_time, p_state.last_write_time)
                            freq = 1 - min(delta / 0.1, 1)
                            w_state.access_frequencies.append(freq)
                        p_state.last_write_time = parsed_time
                        p_state.last_write_file = file_accessed

                    elif target_group == 'DELETE':
                        w_state.delete_count += 1
                        # Deletes have no Writes, so no R1, R2, R4, R5, R6. Just R3.

                    # 4. Check Time Window
                    if _date_diff_in_seconds(curr_times[idx], prev_times[idx]) >= TIME_WINDOW:
                        if w_state.entropy_ratios or w_state.delete_count > 0:
                            vec = _calculate_window_vector(w_state)
                            global_features.append(vec + ['M'])
                        
                        prev_times[idx] = curr_times[idx]
                        w_states[idx] = WindowState()

        except Exception as e:
            print(f"Error processing {session_name}: {e}")

        if global_features:
            with open(output_file, 'a', newline='') as f:
                csv.writer(f).writerows(global_features)

if __name__ == "__main__":
    if not os.path.exists(LOGS_PATH):
        print(f"[!] Error: Log path not found: {LOGS_PATH}")
    else:
        extract_functional_split_redemption_features()
        print("\n[+] Redemption Functional Splitting complete.")