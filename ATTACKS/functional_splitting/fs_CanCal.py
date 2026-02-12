import os
import gzip
import csv
import sys
import json
from collections import defaultdict, Counter
from datetime import datetime

# Add parent directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from scripts.utils.load_config import config, BASE_DIR

# --- CONFIGURATION ---
# CanCal relies on relationships. Splitting functions breaks these relationships.
# We use 5 processes per functional group.
N_SUB_SPLITS = 5
# ---------------------

# CanCal Specific Configs
TIME_WINDOW = config['CanCal']['time_window'] 
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

def rreplace(s, old, new):
    return (s[::-1].replace(old[::-1], new[::-1], 1))[::-1]

def date_diff_in_seconds(dt2, dt1):
    return (dt2 - dt1).total_seconds()

def get_file_details(file_path):
    try:
        if not file_path or file_path.strip() == '': return None, None, None
        _, ext = os.path.splitext(file_path)
        ext = ext.lower() if ext else None
        path_fixed = file_path.replace('\\', '/')
        folder, filename = os.path.split(path_fixed)
        return ext, filename, folder
    except:
        return None, None, None

def create_process_state():
    """Returns a fresh dictionary representing a single process state."""
    return {
        'previous_time': None,
        'current_time': None,
        
        # Window Counters
        'features': defaultdict(int), # n_create, n_delete, n_renamed
        
        # Window Complex State
        'created_exts': set(), 
        'deleted_exts': set(),
        'filename_counts': Counter(),
        'filename_folders': defaultdict(set),

        # Persistent State
        'extensions': set(),
        'ntype_start': 0
    }

def extract_functional_split_cancal_features():
    output_base_path = FEATURES_PATH / f"functional_split_CanCal_{N_SUB_SPLITS}"
    ransomware_logs_path = LOGS_PATH / "ransomware-irp-logs"
    
    output_file = output_base_path / f"ransomware_cancal_features_{TIME_WINDOW}sec.csv"
    
    print(f"[*] Starting CanCal Functional Splitting (N_SUB={N_SUB_SPLITS})")
    print(f"[*] Functional Groups: CREATE, DELETE, RENAME")
    print(f"[*] Total Processes per Session: {N_SUB_SPLITS * 3}")
    print(f"[*] Saving to: {output_file}")

    os.makedirs(output_base_path, exist_ok=True)

    # Initialize CSV with Header
    feature_names = [
        'n_create', 'n_delete', 'n_renamed', 
        'rtype', 'rtype_change', 
        'max_n_file', 'n_folder', 'r_file', 
        'ntype_change', 'Label'
    ]
    with open(output_file, 'w', newline='') as f:
        csv.writer(f).writerow(feature_names)

    for session_name in os.listdir(ransomware_logs_path):
        session_path = ransomware_logs_path / session_name
        
        if not session_name.endswith(".gz") or session_name not in SESSION_PID_MAP:
            continue

        print(f" -> Processing session: {session_name}")
        ransomware_pid = SESSION_PID_MAP.get(session_name)

        # --- CREATE FUNCTIONAL GROUPS ---
        # CanCal focuses on Create, Delete, Rename. 
        # We separate these into 3 distinct teams.
        functional_groups = {
            'CREATE': [create_process_state() for _ in range(N_SUB_SPLITS)],
            'DELETE': [create_process_state() for _ in range(N_SUB_SPLITS)],
            'RENAME': [create_process_state() for _ in range(N_SUB_SPLITS)]
        }

        group_counters = defaultdict(int)
        global_features = []

        try:
            with gzip.open(session_path, 'rt', encoding='utf-8', errors='ignore') as fin:
                next(fin); next(fin) # Skip header

                for line in fin:
                    line = line.strip().split('\t')
                    if len(line) != 23: continue

                    try:
                        major_op = line[7].strip()
                        process_pid = line[4].split('.')[0].strip()
                        post_time = rreplace(line[3].strip(), ':', '.')
                        
                        if process_pid != ransomware_pid: continue

                        parsed_time = datetime.strptime(post_time, '%H:%M:%S.%f')
                        param_code = line[15].strip()
                        file_full_path = line[22].strip()

                        # 1. Determine Target Group
                        target_group = None
                        
                        if major_op == 'IRP_MJ_CREATE':
                            target_group = 'CREATE'
                        elif major_op == 'IRP_MJ_SET_INFORMATION':
                            if param_code == FILE_RENAME_CODE:
                                target_group = 'RENAME'
                            elif param_code == FILE_DELETE_CODE:
                                target_group = 'DELETE'
                        
                        # If operation is not Create/Delete/Rename, we ignore it for CanCal functional split
                        # (Or you could assign it to a 'NOISE' group, but ignoring is cleaner for evasion)
                        if not target_group:
                            continue

                        # 2. Select sub-process (Round Robin)
                        idx = group_counters[target_group] % N_SUB_SPLITS
                        state = functional_groups[target_group][idx]
                        group_counters[target_group] += 1

                        # 3. Update State for this SPECIALIST
                        if state['previous_time'] is None:
                            state['previous_time'] = parsed_time
                            state['ntype_start'] = 0

                        state['current_time'] = parsed_time
                        
                        ext, filename, folder = get_file_details(file_full_path)

                        # Update Logic (Only strict per group)
                        if target_group == 'RENAME':
                            state['features']['n_renamed'] += 1
                            if ext: state['extensions'].add(ext)

                        elif target_group == 'DELETE':
                            state['features']['n_delete'] += 1
                            if ext: 
                                state['extensions'].add(ext)
                                state['deleted_exts'].add(ext)

                        elif target_group == 'CREATE':
                            state['features']['n_create'] += 1
                            if ext: 
                                state['extensions'].add(ext)
                                state['created_exts'].add(ext)
                            
                            if filename:
                                state['filename_counts'][filename] += 1
                                state['filename_folders'][filename].add(folder)

                        # 4. Time Window Check
                        if date_diff_in_seconds(state['current_time'], state['previous_time']) >= TIME_WINDOW:
                            counts = state['features']
                            
                            # Calculate features based on this specialized view
                            ntype_start = state['ntype_start']
                            ntype_end = len(state['extensions'])
                            
                            denom_rtype = ntype_start if ntype_start > 0 else 1
                            rtype = ntype_end / denom_rtype

                            ntype_del_w = len(state['deleted_exts'])
                            ntype_create_w = len(state['created_exts'])
                            denom_change = ntype_create_w if ntype_create_w > 0 else 1
                            rtype_change = ntype_del_w / denom_change # This will be 0 for Creators, and High for Deleters

                            ntype_change = ntype_end - ntype_start

                            if state['filename_counts']:
                                most_common_file, max_count = state['filename_counts'].most_common(1)[0]
                                folder_count = len(state['filename_folders'][most_common_file])
                                folder_count = folder_count if folder_count > 0 else 1
                                max_n_file = max_count
                                n_folder = folder_count
                                r_file = max_count / folder_count
                            else:
                                max_n_file = 0; n_folder = 0; r_file = 0

                            vector = [
                                counts['n_create'], counts['n_delete'], counts['n_renamed'],
                                rtype, rtype_change,
                                max_n_file, n_folder, r_file,
                                ntype_change,
                                'M'
                            ]

                            # Only save non-empty vectors
                            if any(x > 0 for x in vector[:3]): 
                                global_features.append(vector)

                            # Reset
                            state['previous_time'] = state['current_time']
                            state['ntype_start'] = ntype_end
                            state['features'].clear()
                            state['created_exts'].clear()
                            state['deleted_exts'].clear()
                            state['filename_counts'].clear()
                            state['filename_folders'].clear()

                    except Exception:
                        continue
            
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
        extract_functional_split_cancal_features()
        print("\n[+] CanCal Functional Splitting complete.")