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
N_SPLITS = 10 
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

def extract_split_cancal_features():
    output_base_path = FEATURES_PATH / f"ransomware_split_CanCal_{N_SPLITS}"
    ransomware_logs_path = LOGS_PATH / "ransomware-irp-logs"
    
    output_file = output_base_path / f"ransomware_cancal_features_{TIME_WINDOW}sec.csv"
    
    print(f"[*] Starting CanCal Process Splitting (N={N_SPLITS})")
    print(f"[*] Time Window: {TIME_WINDOW} seconds")
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

        # --- INITIALIZE N SPLIT STATES ---
        split_states = []
        for i in range(N_SPLITS):
            split_states.append({
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
            })

        global_features = []
        op_counter = 0

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

                        # --- ROUND ROBIN DISTRIBUTION ---
                        target_split_idx = op_counter % N_SPLITS
                        state = split_states[target_split_idx]
                        op_counter += 1
                        # --------------------------------

                        # Initialize time for this split
                        if state['previous_time'] is None:
                            state['previous_time'] = parsed_time
                            state['ntype_start'] = 0 # Snapshot ntype start

                        state['current_time'] = parsed_time
                        
                        # Parse File Details
                        ext, filename, folder = get_file_details(file_full_path)

                        # --- CORE LOGIC (Applied to Split State) ---
                        if major_op == 'IRP_MJ_SET_INFORMATION':
                            if param_code == FILE_RENAME_CODE:
                                state['features']['n_renamed'] += 1
                                if ext: state['extensions'].add(ext)

                            elif param_code == FILE_DELETE_CODE:
                                state['features']['n_delete'] += 1
                                if ext: 
                                    state['extensions'].add(ext)
                                    state['deleted_exts'].add(ext)

                        elif major_op == 'IRP_MJ_CREATE':
                            state['features']['n_create'] += 1
                            if ext: 
                                state['extensions'].add(ext)
                                state['created_exts'].add(ext)
                            
                            if filename:
                                state['filename_counts'][filename] += 1
                                state['filename_folders'][filename].add(folder)

                        # --- TIME WINDOW CHECK (For specific Split) ---
                        if date_diff_in_seconds(state['current_time'], state['previous_time']) >= TIME_WINDOW:
                            counts = state['features']
                            
                            # Calculate complex features for this split
                            ntype_start = state['ntype_start']
                            ntype_end = len(state['extensions'])
                            
                            # 1. rtype
                            denom_rtype = ntype_start if ntype_start > 0 else 1
                            rtype = ntype_end / denom_rtype

                            # 2. rtype_change
                            ntype_del_w = len(state['deleted_exts'])
                            ntype_create_w = len(state['created_exts'])
                            denom_change = ntype_create_w if ntype_create_w > 0 else 1
                            rtype_change = ntype_del_w / denom_change

                            # 3. ntype_change
                            ntype_change = ntype_end - ntype_start

                            # 4. Ransom Note Features
                            if state['filename_counts']:
                                most_common_file, max_count = state['filename_counts'].most_common(1)[0]
                                folder_count = len(state['filename_folders'][most_common_file])
                                folder_count = folder_count if folder_count > 0 else 1
                                
                                max_n_file = max_count
                                n_folder = folder_count
                                r_file = max_count / folder_count
                            else:
                                max_n_file = 0; n_folder = 0; r_file = 0

                            # Construct Vector
                            # Order: n_create, n_delete, n_renamed, rtype, rtype_change, max_n_file, n_folder, r_file, ntype_change
                            vector = [
                                counts['n_create'], counts['n_delete'], counts['n_renamed'],
                                rtype, rtype_change,
                                max_n_file, n_folder, r_file,
                                ntype_change,
                                'M' # Label
                            ]

                            # Only save if activity occurred
                            numeric_part = vector[:-1]
                            if any(x > 0 for x in numeric_part): # Simple check if vector is empty
                                global_features.append(vector)

                            # Reset State for Next Window
                            state['previous_time'] = state['current_time']
                            state['ntype_start'] = ntype_end # Update baseline
                            
                            state['features'].clear()
                            state['created_exts'].clear()
                            state['deleted_exts'].clear()
                            state['filename_counts'].clear()
                            state['filename_folders'].clear()

                    except Exception:
                        continue
            
            # Save vectors for this session
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
        extract_split_cancal_features()
        print("\n[+] CanCal Process Splitting complete.")