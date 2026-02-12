import os
import gzip
import csv
import sys
import json
from collections import defaultdict
from datetime import datetime

# Add parent directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from scripts.utils.load_config import config, BASE_DIR

# --- CONFIGURATION ---
# The paper achieved full evasion against RWGuard with 8 processes per group (64 total).
N_SUB_SPLITS = 8 
# ---------------------

# RWGuard Specific Configs
TIME_WINDOW = config['RWGuard']['time_window'] 
FEATURES_PATH = BASE_DIR / 'ATTACKS' 
LOGS_PATH = BASE_DIR / 'data' / 'ShieldFS-dataset'

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

def rreplace(s, old, new):
    """Helper to parse timestamps in logs."""
    return (s[::-1].replace(old[::-1], new[::-1], 1))[::-1]

def date_diff_in_seconds(dt2, dt1):
    return (dt2 - dt1).total_seconds()

def update_feature(state, key):
    """Updates the counter for a specific split state."""
    state['counts'][key] += 1

def create_process_state():
    """Returns a fresh dictionary representing a single process state."""
    return {
        'counts': {k: 0 for k in [
            'READ', 'WRITE', 'OPEN', 'CLOSE',
            'FAST_READ', 'FAST_WRITE', 'FAST_OPEN', 'FAST_CLOSE']},
        'previous_time': None,
        'current_time': None
    }

def extract_functional_split_rwguard_features():
    output_base_path = FEATURES_PATH / f"functional_split_RWGuard_{N_SUB_SPLITS}"
    ransomware_logs_path = LOGS_PATH / "ransomware-irp-logs"
    
    # The output filename matches RWGuard's expected format
    output_file = output_base_path / f"ransomware_rwguard_features_{TIME_WINDOW}sec.csv"
    
    print(f"[*] Starting RWGuard Functional Splitting (N_SUB={N_SUB_SPLITS})")
    print(f"[*] Total Functional Groups: 8")
    print(f"[*] Total Processes per Session: {N_SUB_SPLITS * 8}")
    print(f"[*] Saving to: {output_file}")

    # Create directory
    os.makedirs(output_base_path, exist_ok=True)

    # Clear/Create output file
    with open(output_file, 'w', newline='') as f:
        pass 

    for session_name in os.listdir(ransomware_logs_path):
        session_path = ransomware_logs_path / session_name
        
        if not session_name.endswith(".gz") or session_name not in SESSION_PID_MAP:
            continue

        print(f" -> Processing session: {session_name}")
        ransomware_pid = SESSION_PID_MAP.get(session_name)

        # --- CREATE FUNCTIONAL GROUPS ---
        # RWGuard tracks 8 specific features. We create a group for EACH.
        # This maps the feature key (e.g., 'FAST_WRITE') to a list of N processes.
        functional_groups = {
            'READ':       [create_process_state() for _ in range(N_SUB_SPLITS)],
            'WRITE':      [create_process_state() for _ in range(N_SUB_SPLITS)],
            'OPEN':       [create_process_state() for _ in range(N_SUB_SPLITS)],
            'CLOSE':      [create_process_state() for _ in range(N_SUB_SPLITS)],
            'FAST_READ':  [create_process_state() for _ in range(N_SUB_SPLITS)],
            'FAST_WRITE': [create_process_state() for _ in range(N_SUB_SPLITS)],
            'FAST_OPEN':  [create_process_state() for _ in range(N_SUB_SPLITS)],
            'FAST_CLOSE': [create_process_state() for _ in range(N_SUB_SPLITS)]
        }

        # Counters for Round Robin within groups
        group_counters = defaultdict(int)

        global_features = [] # Store all vectors for this session

        try:
            with gzip.open(session_path, 'rt', encoding='utf-8', errors='ignore') as fin:
                next(fin); next(fin) # Skip headers

                for line in fin:
                    line = line.strip().split('\t')
                    if len(line) != 23: continue

                    try:
                        major_op = line[7].strip()
                        operation_type = line[0].strip()
                        process_pid = line[4].split('.')[0].strip()
                        post_time = rreplace(line[3].strip(), ':', '.')
                        
                        if process_pid != ransomware_pid: continue

                        parsed_time = datetime.strptime(post_time, '%H:%M:%S.%f')

                        # 1. Determine Target Feature (and thus Functional Group)
                        target_feature = None
                        
                        # Check REGULAR vs FAST IO
                        prefix = ""
                        if operation_type == FAST_IO:
                            prefix = "FAST_"
                        elif operation_type != REGULAR_IO:
                            continue # Skip unrelated IO types

                        # Map operation to feature name
                        if major_op in ACTIONS['FILE_READ']:
                            target_feature = prefix + 'READ'
                        elif major_op in ACTIONS['FILE_WRITE']:
                            target_feature = prefix + 'WRITE'
                        elif major_op in ACTIONS['IRP_OPEN']:
                            target_feature = prefix + 'OPEN'
                        elif major_op in ACTIONS['IRP_CLOSE']:
                            target_feature = prefix + 'CLOSE'

                        # If operation is not one of the monitored 8, skip
                        if not target_feature:
                            continue

                        # 2. Select specific sub-process within that group (Round Robin)
                        idx = group_counters[target_feature] % N_SUB_SPLITS
                        state = functional_groups[target_feature][idx]
                        group_counters[target_feature] += 1

                        # 3. Update State (Time & Count)
                        if state['previous_time'] is None:
                            state['previous_time'] = parsed_time
                        state['current_time'] = parsed_time

                        # ONLY increment the specific feature for this group
                        # A 'FAST_WRITE' process will never see a 'READ' increment here
                        state['counts'][target_feature] += 1

                        # 4. Check Time Window for this SPECIFIC split process
                        if date_diff_in_seconds(state['current_time'], state['previous_time']) >= TIME_WINDOW:
                            counts = state['counts']
                            
                            if any(counts.values()):
                                global_features.append(list(counts.values()) + ['M'])
                            
                            state['previous_time'] = state['current_time']
                            # Reset counts
                            for k in counts: counts[k] = 0

                    except Exception as e:
                        continue

            # Save collected features
            if global_features:
                with open(output_file, 'a', newline='') as f:
                    csv.writer(f).writerows(global_features)
                print(f"    -> Generated {len(global_features)} vectors.")

        except Exception as e:
            print(f"Error processing {session_name}: {e}")

if __name__ == "__main__":
    if not os.path.exists(LOGS_PATH):
        print(f"[!] Error: Log path not found: {LOGS_PATH}")
    else:
        extract_functional_split_rwguard_features()
        print("\n[+] RWGuard Functional Splitting complete.")