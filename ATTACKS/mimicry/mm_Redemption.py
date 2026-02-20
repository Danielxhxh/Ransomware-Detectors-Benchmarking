import json
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
# Mimicry Strategy: Dilute High Entropy Writes with Low Entropy Dummies
# For every 1 Real Encryption, how many Dummy (Zero Entropy) writes to inject?
DUMMY_WRITES_PER_OP = 5  
# (1.0 + 0 + 0 + 0 + 0 + 0) / 6 = 0.16 Average Ratio (Safe!)

# Rate Limiting (to lower R6 Frequency score)
MAX_OPS_PER_WINDOW = 20

# Redemption Configs
TIME_WINDOW = config['Redemption']['time_window'] 
FEATURES_PATH = BASE_DIR / 'ATTACKS' 
LOGS_PATH = BASE_DIR / 'data' / 'ShieldFS-dataset'

ACTIONS = {
    'FILE_READ': ['IRP_MJ_READ'],
    'FILE_WRITE': ['IRP_MJ_WRITE'],
    'FILE_RENAME_MOVED': ['IRP_MJ_SET_INFORMATION'],
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
    ops_in_window: int = 0  # Rate Limiter Counter

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
    # R1: Average Entropy Ratio (The target of our attack)
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

def create_mimic_state():
    return (PersistentState(), WindowState(), None, None) # p_state, w_state, prev_time, curr_time

def extract_mimicry_redemption_features():
    output_base_path = FEATURES_PATH / f"mimicry_Redemption"
    ransomware_logs_path = LOGS_PATH / "ransomware-irp-logs"
    
    output_file = output_base_path / f"ransomware_redemption_features_{TIME_WINDOW}sec.csv"
    
    print(f"[*] Starting Redemption Mimicry Attack (Dilution Strategy)")
    print(f"[*] Injecting {DUMMY_WRITES_PER_OP} dummy low-entropy writes per real write.")
    print(f"[*] Limiting to {MAX_OPS_PER_WINDOW} ops per window.")
    
    os.makedirs(output_base_path, exist_ok=True)
    with open(output_file, 'w', newline='') as f: pass 

    for session_name in os.listdir(ransomware_logs_path):
        session_path = ransomware_logs_path / session_name
        
        if not session_name.endswith(".gz") or session_name not in SESSION_PID_MAP: continue

        print(f" -> Processing session: {session_name}")
        ransomware_pid = SESSION_PID_MAP.get(session_name)

        # We start with 1 mimic process state
        mimic_states = [create_mimic_state()]
        current_proc_idx = 0
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

                    if file_accessed in ('0.000000000000000', 'cannot get name', ''): continue

                    # Get Current State
                    p_state, w_state, prev_time, curr_time = mimic_states[current_proc_idx]
                    
                    # Init Time
                    if prev_time is None: 
                        prev_time = parsed_time
                        mimic_states[current_proc_idx] = (p_state, w_state, prev_time, parsed_time)
                    
                    curr_time = parsed_time
                    mimic_states[current_proc_idx] = (p_state, w_state, prev_time, curr_time)

                    # --- RATE LIMIT CHECK ---
                    if w_state.ops_in_window >= MAX_OPS_PER_WINDOW:
                        # Throttle! Move to new state bucket (simulate sleep/new window)
                        mimic_states.append(create_mimic_state())
                        current_proc_idx += 1
                        # Re-fetch new empty state
                        p_state, w_state, prev_time, curr_time = mimic_states[current_proc_idx]
                        prev_time = parsed_time # Start new window now
                        curr_time = parsed_time
                        mimic_states[current_proc_idx] = (p_state, w_state, prev_time, curr_time)

                    # --- UPDATE STATE ---
                    try:
                        offset_hex = line[14].strip()
                        offset = int(offset_hex, 16) if offset_hex.startswith('0x') else int(offset_hex)
                    except: offset = 0

                    if major_op in ACTIONS['FILE_READ']:
                        ent = _safe_float(line[21])
                        if ent is not None:
                            p_state.read_history[file_accessed][offset] = ent
                        w_state.ops_in_window += 1

                    elif major_op in ACTIONS['FILE_WRITE']:
                        ent = _safe_float(line[21])
                        
                        # Real Write Calculation
                        prev_read = p_state.read_history.get(file_accessed, {}).get(offset)
                        ratio = 0.0
                        if prev_read and ent and ent > prev_read:
                            ratio = 1.0 - (prev_read / ent)
                        w_state.entropy_ratios.append(ratio)
                        
                        # --- MIMICRY INJECTION ---
                        # Inject Dummies to crash the average
                        for _ in range(DUMMY_WRITES_PER_OP):
                            w_state.entropy_ratios.append(0.0) # Dummy 0 entropy ratio
                            # Also inject dummy modified block to keep R2 consistent with activity volume
                            w_state.modified_blocks.add(f"dummy_{datetime.now().microsecond}")

                        w_state.modified_blocks.add(f"{file_accessed}|{offset // 4096}")
                        w_state.dir_writes[os.path.split(file_accessed.replace("\\", "/"))[0]].add(os.path.split(file_accessed)[1])
                        w_state.file_classes.add(_get_file_class(file_accessed))
                        
                        if p_state.last_write_time and p_state.last_write_file != file_accessed:
                            delta = _date_diff_in_seconds(parsed_time, p_state.last_write_time)
                            freq = 1 - min(delta / 0.1, 1)
                            w_state.access_frequencies.append(freq)
                        
                        p_state.last_write_time = parsed_time
                        p_state.last_write_file = file_accessed
                        w_state.ops_in_window += 1

                    elif major_op in ACTIONS['FILE_RENAME_MOVED']:
                        w_state.delete_count += 1
                        w_state.ops_in_window += 1

                    # --- CHECK TIME WINDOW ---
                    if _date_diff_in_seconds(curr_time, prev_time) >= TIME_WINDOW:
                        if w_state.entropy_ratios or w_state.delete_count > 0:
                            vec = _calculate_window_vector(w_state)
                            global_features.append(vec + ['M'])
                        
                        # Reset Window
                        # We must update the tuple in the list because tuples are immutable
                        new_w_state = WindowState()
                        mimic_states[current_proc_idx] = (p_state, new_w_state, curr_time, curr_time)

        except Exception as e:
            print(f"Error processing {session_name}: {e}")

        if global_features:
            with open(output_file, 'a', newline='') as f:
                csv.writer(f).writerows(global_features)

if __name__ == "__main__":
    if not os.path.exists(LOGS_PATH):
        print(f"[!] Error: Log path not found: {LOGS_PATH}")
    else:
        extract_mimicry_redemption_features()
        print("\n[+] Redemption Mimicry Attack complete.")