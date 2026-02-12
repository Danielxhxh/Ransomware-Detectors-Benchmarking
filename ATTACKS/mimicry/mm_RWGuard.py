import os
import gzip
import csv
import sys
import json
from collections import defaultdict
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from scripts.utils.load_config import config, BASE_DIR

# --- CONFIGURATION ---
# RWGuard detects high frequency. We mimic a "Slow Benign App".
# Target: Max X operations per Time Window.
# A typical benign app might do 10-20 ops per few seconds.
MAX_OPS_PER_WINDOW = 10 
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
    return (s[::-1].replace(old[::-1], new[::-1], 1))[::-1]

def date_diff_in_seconds(dt2, dt1):
    return (dt2 - dt1).total_seconds()

def create_mimic_state():
    return {
        'counts': {k: 0 for k in [
            'READ', 'WRITE', 'OPEN', 'CLOSE',
            'FAST_READ', 'FAST_WRITE', 'FAST_OPEN', 'FAST_CLOSE']},
        'previous_time': None,
        'current_time': None,
        'ops_in_current_window': 0
    }

def extract_mimicry_rwguard_features():
    output_base_path = FEATURES_PATH / "mimicry_RWGuard"
    ransomware_logs_path = LOGS_PATH / "ransomware-irp-logs"
    
    output_file = output_base_path / f"ransomware_rwguard_features_{TIME_WINDOW}sec.csv"
    
    print(f"[*] Starting RWGuard Mimicry Attack (Rate Limiting)")
    print(f"[*] Max Ops Per Window: {MAX_OPS_PER_WINDOW}")
    print(f"[*] Saving to: {output_file}")

    os.makedirs(output_base_path, exist_ok=True)
    with open(output_file, 'w', newline='') as f:
        pass 

    for session_name in os.listdir(ransomware_logs_path):
        session_path = ransomware_logs_path / session_name
        
        if not session_name.endswith(".gz") or session_name not in SESSION_PID_MAP:
            continue

        print(f" -> Processing session: {session_name}")
        ransomware_pid = SESSION_PID_MAP.get(session_name)

        # We simulate a "queue" of threads/processes. 
        # Ideally, Mimicry uses 1 process that sleeps, but for simulation, 
        # if the rate is exceeded, we basically assume the activity is pushed 
        # to a new time window or a new "clean" state.
        mimic_states = [create_mimic_state()]
        current_proc_idx = 0

        global_features = [] 

        try:
            with gzip.open(session_path, 'rt', encoding='utf-8', errors='ignore') as fin:
                next(fin); next(fin)

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

                        # Get current active mimic state
                        state = mimic_states[current_proc_idx]

                        # Initialize time
                        if state['previous_time'] is None:
                            state['previous_time'] = parsed_time
                        state['current_time'] = parsed_time

                        # --- RATE LIMIT CHECK ---
                        # If adding this op would exceed the "Benign Speed Limit" for this window
                        if state['ops_in_current_window'] >= MAX_OPS_PER_WINDOW:
                            # In a real attack, the malware sleeps here.
                            # In simulation, we finalize this window (it's safe/full) 
                            # and spin up a fresh state/window to continue immediately.
                            mimic_states.append(create_mimic_state())
                            current_proc_idx += 1
                            state = mimic_states[current_proc_idx]
                            state['previous_time'] = parsed_time
                            state['current_time'] = parsed_time

                        # --- UPDATE FEATURE ---
                        key = None
                        if operation_type == REGULAR_IO:
                            for k, ops in ACTIONS.items():
                                if major_op in ops: key = k.split('_')[1]
                        elif operation_type == FAST_IO:
                            for k, ops in ACTIONS.items():
                                if major_op in ops: key = 'FAST_' + k.split('_')[1]

                        if key:
                            state['counts'][key] += 1
                            state['ops_in_current_window'] += 1

                        # --- TIME WINDOW CHECK ---
                        # Standard flushing logic
                        if date_diff_in_seconds(state['current_time'], state['previous_time']) >= TIME_WINDOW:
                            counts = state['counts']
                            if any(counts.values()):
                                global_features.append(list(counts.values()) + ['M'])
                            
                            # Reset for next window
                            state['previous_time'] = state['current_time']
                            state['ops_in_current_window'] = 0
                            for k in counts: counts[k] = 0

                    except Exception as e:
                        continue

            # Flush remaining vectors
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
        extract_mimicry_rwguard_features()
        print("\n[+] RWGuard Mimicry Attack complete.")