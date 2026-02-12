import os
import gzip
import csv
import json
import sys
import re
from collections import defaultdict

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from scripts.utils.load_config import config, BASE_DIR

# --- CONFIGURATION ---
# Ratio: 1 : 16 : 13 : 1
TARGET_RATIOS = {'DL': 1, 'RD': 16, 'WT': 13, 'RN': 1}
TARGET_VOLUME_PERCENT = 0.83  # Max 0.83% of files per process

FEATURES_PATH = BASE_DIR / 'ATTACKS' 
LOGS_PATH = BASE_DIR / 'data' / 'ShieldFS-dataset'
TIER = config['ShieldFS']['tiers']

ACTIONS = {
    'FILE_READ': ['IRP_MJ_READ'],
    'FILE_WRITE': ['IRP_MJ_WRITE'],
    'FILE_RENAME_MOVED': ['IRP_MJ_SET_INFORMATION'],
    'DIRECTORY_LISTING': ['IRP_MJ_DIRECTORY_CONTROL.IRP_MN_QUERY_DIRECTORY'],
}

TICKS_EXP = {
    1: [0.11, 0.13, 0.17, 0.22, 0.28, 0.33, 0.46, 0.63, 0.83, 1, 1.37,
        1.78, 2.3, 3, 3.92, 5, 6.66, 8.66, 11.25, 14.68, 19.1, 24.71, 32.1, 41, 54, 70.5, 91, 100],
    2: [0.13,  0.22, 0.37,  0.63, 1, 1.79, 3, 5, 8.65, 14.68, 24.71, 41, 70.5, 100],
    3: [0.17, 0.37, 0.83, 1.78, 3.92, 8.66, 19.1, 41, 100],
    4: [0.22, 0.63, 1.78, 5, 14.68, 41, 100],
    5: [0.28, 1, 3.92, 14.68, 54, 100],
    6: [0.37, 1.78, 8.65, 41, 100],
    7: [0.48, 3, 19.1, 100],
    8: [0.63, 5, 41, 100],
    9: [0.83, 8.66, 100],
    10: [1, 14.68, 100],
    11: [1.37, 24.7, 100],
    12: [1.78, 41, 100],
    13: [2.3, 70.5, 100],
    14: [3, 100],
    15: [3.92, 100],
    16: [5, 100],
    17: [6.66, 100],
    18: [8.66, 100],
    19: [11.25, 100],
    20: [14.68, 100],
    21: [19.1, 100],
    22: [24.71, 100],
    23: [32.1, 100],
    24: [41, 100],
    25: [54, 100],
    26: [70.5, 100],
    27: [91, 100],
    28: [100]
}


SESSION_PID_MAP = {
    '480bd1ecb1b969e6677c1e11a30cd985e4244e5de04956e2dbb0e6b97c42027e.gz': '2616',
    '09c278fc0ae3a36170a71e65bba9f92da086fca941ba93051811bf16c6b67f64.gz': '2060',
    '0d6fb25cde440df0d2b6a676e86b23c47c298f60f8ec461805cc4cd77dd9f730.gz': '3680',
    'c80d611b38c6ea23cf9d564111a24f245f48df48a5341da896912054dd7d9529.gz': '3684'
}

def generate_all_ticks_csv(output_folder):
    folder = output_folder / f"tier{TIER}"
    all_ticks_path = folder / "all_ticks.csv"
    print(f"[*] Aggregating ticks in: {folder}")
    
    # ... (Same aggregation logic as before) ...
    with open(all_ticks_path, 'w', newline='') as out_fp:
        writer = csv.writer(out_fp)
        for tick_file in sorted(folder.glob("tick*.csv")):
             with open(tick_file, 'r') as in_fp:
                writer.writerows(csv.reader(in_fp))
    print(f"[+] Generated {all_ticks_path}")

def load_machine_statistics_ransomware():
    statistics_file = BASE_DIR / 'utilities' / 'ShieldFS' / 'statistics' / 'machine_statistics_virtual.txt'
    with open(statistics_file, 'r') as fp:
        for ln in fp:
            try:
                els = ln.split('\t')
                return int(els[1]), int(els[2]), json.loads(els[3])
            except: pass
    return 0, 0, {}

def create_mimic_state():
    return {
        'current_tick': 0,
        'features': defaultdict(list),
        'seen_files': set(),
        'seen_extensions': set(),
        'num_folder_listings': 0,
        'num_files_read': 0,
        'num_files_written': 0,
        'num_files_renamedmoved': 0,
        'write_entropy': 0.0,
        'nr_files_accessed': 0
    }

def calculate_file_type_coverage(total, seen_exts, counts_dict):
    sum_counts = sum(counts_dict.get(ext, 0) for ext in seen_exts)
    return float(total) / float(sum_counts) if sum_counts != 0 else 0

def extract_mimicry_shieldfs_features():
    output_base_path = FEATURES_PATH / "mimicry_ShieldFS"
    ransomware_logs_path = LOGS_PATH / "ransomware-irp-logs"
    
    print(f"[*] Starting Mimicry Attack (Target: Benign Profile 1:16:13:1)")
    print(f"[*] Volume Limit: {TARGET_VOLUME_PERCENT}% per process")

    number_folders, number_files, extension_counts = load_machine_statistics_ransomware()
    os.makedirs(output_base_path / f"tier{TIER}", exist_ok=True)

    # Calculate Volume Limit (Max files a single mimic process can touch)
    MAX_FILES_PER_PROCESS = int(number_files * (TARGET_VOLUME_PERCENT / 100.0))
    print(f"[*] Max Files per Process: {MAX_FILES_PER_PROCESS}")

    for session_name in os.listdir(ransomware_logs_path):
        session_path = ransomware_logs_path / session_name
        if not session_name.endswith(".gz") or session_name not in SESSION_PID_MAP: continue

        print(f" -> Processing session: {session_name}")
        
        # We start with 1 mimic process
        mimic_states = [create_mimic_state()]
        current_proc_idx = 0
        
        try:
            ransomware_pid = SESSION_PID_MAP.get(session_name)
            
            with gzip.open(session_path, 'rt', encoding='utf-8') as fin:
                for line in fin:
                    line = line.split("\t")
                    if len(line) != 23: continue

                    major_op = line[7].strip()
                    minor_op = line[8].strip()
                    file_accessed = line[22].strip()
                    process_pid = line[4].split('.')[0].strip()
                    m_m = major_op + '.' + minor_op
                    
                    if process_pid == ransomware_pid:
                        state = mimic_states[current_proc_idx]
                        
                        # --- ROTATION LOGIC ---
                        # If this process is full (hit volume limit), spawn a new one
                        if state['nr_files_accessed'] >= MAX_FILES_PER_PROCESS:
                            mimic_states.append(create_mimic_state())
                            current_proc_idx += 1
                            state = mimic_states[current_proc_idx]

                        change = False
                        
                        # --- REAL OPERATIONS ---
                        if major_op in ACTIONS['FILE_READ']:
                            state['num_files_read'] += 1
                            change = True
                        elif major_op in ACTIONS['FILE_WRITE']:
                            state['num_files_written'] += 1
                            state['write_entropy'] += float(line[21]) # Add REAL entropy
                            change = True
                        elif major_op in ACTIONS['FILE_RENAME_MOVED']:
                            state['num_files_renamedmoved'] += 1
                            change = True
                            
                            # --- MIMICRY INJECTION (THE TRICK) ---
                            # Every time we encrypt (Rename) a file, we force the ratio.
                            # We need 15 Dummy Reads and 12 Dummy Writes (Low Entropy)
                            
                            state['num_files_read'] += 15
                            
                            state['num_files_written'] += 12
                            # Dummy writes have 0 entropy. We just don't add to 'write_entropy'.
                            # The average calculation later will divide (RealEntropy + 0) / (RealWrites + 12)
                            
                            # Also inject 1 Dummy Listing to match the profile
                            state['num_folder_listings'] += 1

                        elif m_m in ACTIONS['DIRECTORY_LISTING']:
                            state['num_folder_listings'] += 1
                            change = True

                        # --- TICK CHECK (Same as always) ---
                        if change and file_accessed not in ('0.000000000000000', 'cannot get name'):
                            if file_accessed not in state['seen_files']:
                                state['seen_files'].add(file_accessed)
                                state['nr_files_accessed'] += 1
                                state['seen_extensions'].add(os.path.splitext(file_accessed)[1])

                            percentage_file_accessed = float(len(state['seen_files'])) / float(number_files) * 100
                            
                            # We use TIER 1 logic for simplicity or whatever tier is configured
                            # Ensure we handle the tick lookup safely
                            current_tick = state['current_tick']
                            # Assuming TICKS_EXP is fully populated or we check bounds
                            ticks_list = TICKS_EXP.get(TIER, [])
                            
                            if current_tick < len(ticks_list) and percentage_file_accessed >= ticks_list[current_tick]:
                                
                                # Calculate Features
                                f_coverage = calculate_file_type_coverage(state['nr_files_accessed'], state['seen_extensions'], extension_counts)
                                
                                a = float(state['num_folder_listings']) / float(number_folders)
                                b = float(state['num_files_read']) / float(number_files)
                                c = float(state['num_files_written']) / float(number_files)
                                d = float(state['num_files_renamedmoved']) / float(number_files)
                                
                                # ENTROPY DILUTION IS AUTOMATIC HERE
                                # e = (Sum Real Entropies) / (Real Writes + Dummy Writes)
                                e = state['write_entropy'] / float(state['num_files_written']) if state['num_files_written'] > 0 else 0
                                
                                state['features'][current_tick].append([a, b, c, d, f_coverage, e, 'M'])
                                
                                # Reset
                                state['num_folder_listings'] = 0
                                state['num_files_read'] = 0
                                state['num_files_written'] = 0
                                state['num_files_renamedmoved'] = 0
                                state['write_entropy'] = 0.0
                                state['nr_files_accessed'] = 0
                                state['seen_extensions'].clear()
                                state['seen_files'].clear()
                                state['current_tick'] += 1

        except Exception as e:
            print(f"Error {session_name}: {e}")

        # Save features
        for state in mimic_states:
             for tick, feats in state['features'].items():
                with open(output_base_path / f"tier{TIER}" / f"tick{tick}.csv", 'a', newline='') as fp:
                    csv.writer(fp).writerows(feats)

    generate_all_ticks_csv(output_base_path)

if __name__ == "__main__":
    if not os.path.exists(LOGS_PATH):
        print(f"[!] Log path not found: {LOGS_PATH}")
    else:
        extract_mimicry_shieldfs_features()
        print("\n[+] Mimicry Attack Complete.")