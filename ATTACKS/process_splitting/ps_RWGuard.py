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
N_SPLITS = 10  # <--- Change this to 10, 50, 100 to test evasion
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

def extract_split_rwguard_features():
    output_base_path = FEATURES_PATH / f"ransomware_split_RWGuard_{N_SPLITS}"
    ransomware_logs_path = LOGS_PATH / "ransomware-irp-logs"
    
    # The output filename matches RWGuard's expected format
    output_file = output_base_path / f"ransomware_rwguard_features_{TIME_WINDOW}sec.csv"
    
    print(f"[*] Starting RWGuard Process Splitting (N={N_SPLITS})")
    print(f"[*] Time Window: {TIME_WINDOW} seconds")
    print(f"[*] Saving to: {output_file}")

    # Create directory
    os.makedirs(output_base_path, exist_ok=True)

    # Clear/Create output file
    # We open it in 'w' first to wipe it, then 'a' inside the loop
    with open(output_file, 'w', newline='') as f:
        pass 

    for session_name in os.listdir(ransomware_logs_path):
        session_path = ransomware_logs_path / session_name
        
        if not session_name.endswith(".gz") or session_name not in SESSION_PID_MAP:
            continue

        print(f" -> Processing session: {session_name}")
        ransomware_pid = SESSION_PID_MAP.get(session_name)

        # --- INITIALIZE N SPLIT STATES ---
        # Each split needs its own counters AND its own time tracking
        split_states = []
        for i in range(N_SPLITS):
            split_states.append({
                'counts': {k: 0 for k in [
                    'READ', 'WRITE', 'OPEN', 'CLOSE',
                    'FAST_READ', 'FAST_WRITE', 'FAST_OPEN', 'FAST_CLOSE']},
                'previous_time': None,
                'current_time': None
            })

        global_features = [] # Store all generated vectors for this session
        op_counter = 0 # For Round Robin

        try:
            with gzip.open(session_path, 'rt', encoding='utf-8', errors='ignore') as fin:
                # Skip headers
                next(fin)
                next(fin)

                for line in fin:
                    line = line.strip().split('\t')
                    if len(line) != 23: continue

                    try:
                        major_op = line[7].strip()
                        operation_type = line[0].strip()
                        process_pid = line[4].split('.')[0].strip()
                        post_time = rreplace(line[3].strip(), ':', '.')
                        
                        # Only process ransomware lines
                        if process_pid != ransomware_pid:
                            continue

                        parsed_time = datetime.strptime(post_time, '%H:%M:%S.%f')

                        # --- ROUND ROBIN DISTRIBUTION ---
                        target_split_idx = op_counter % N_SPLITS
                        state = split_states[target_split_idx]
                        op_counter += 1
                        # --------------------------------

                        # Initialize time for this specific split if new
                        if state['previous_time'] is None:
                            state['previous_time'] = parsed_time
                        
                        state['current_time'] = parsed_time

                        # Update features for this SPECIFIC split
                        if operation_type == REGULAR_IO:
                            for key, ops in ACTIONS.items():
                                if major_op in ops:
                                    update_feature(state, key.split('_')[1])
                        elif operation_type == FAST_IO:
                            for key, ops in ACTIONS.items():
                                if major_op in ops:
                                    update_feature(state, 'FAST_' + key.split('_')[1])

                        # Check Time Window for this SPECIFIC split
                        # Logic: Has THIS split been running longer than TIME_WINDOW since its last flush?
                        if date_diff_in_seconds(state['current_time'], state['previous_time']) >= TIME_WINDOW:
                            counts = state['counts']
                            
                            # Only save if there was actual activity
                            if any(counts.values()):
                                # Append 'M' for Malicious
                                global_features.append(list(counts.values()) + ['M'])
                            
                            # Reset this split's window and counters
                            state['previous_time'] = state['current_time']
                            for k in counts:
                                counts[k] = 0

                    except Exception as e:
                        continue

            # Save collected features for this session
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
        extract_split_rwguard_features()
        print("\n[+] RWGuard Process Splitting complete.")