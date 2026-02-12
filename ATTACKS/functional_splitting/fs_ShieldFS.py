import os
import gzip
import csv
import json
import sys
import re
from collections import defaultdict

# Add the parent directory to the path so we can import 'scripts'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from scripts.utils.load_config import config, BASE_DIR

# --- CONFIGURATION ---
# The paper suggests 5 processes per group (20 total) achieves ~0% detection.
N_SUB_SPLITS = 5  

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

    def extract_tick_number(path):
        match = re.search(r"tick(\d+)\.csv", str(path))
        return int(match.group(1)) if match else -1

    tick_files = sorted(folder.glob("tick*.csv"), key=extract_tick_number)
    if not tick_files:
        print(f"[!] No tick files found in {folder}")
        return

    with open(all_ticks_path, 'w', newline='') as out_fp:
        writer = csv.writer(out_fp)
        count = 0
        for tick_file in tick_files:
            try:
                with open(tick_file, 'r', newline='') as in_fp:
                    reader = csv.reader(in_fp)
                    for row in reader:
                        writer.writerow(row)
                        count += 1
            except Exception as e:
                print(f"Failed to read {tick_file}: {e}")

    print(f"[+] Generated {all_ticks_path} with {count} rows.")
    
def calculate_file_type_coverage(total_files_accessed, currently_seen_extensions, extension_counts_dict):
    sum_counts = sum(extension_counts_dict.get(ext, 0) for ext in currently_seen_extensions)
    return float(total_files_accessed) / float(sum_counts) if sum_counts != 0 else 0

def load_machine_statistics_ransomware():
    statistics_file = BASE_DIR / 'utilities' / 'ShieldFS' / 'statistics' / 'machine_statistics_virtual.txt'
    with open(statistics_file, 'r') as fp:
        for ln in fp:
            try:
                els = ln.split('\t')
                return int(els[1]), int(els[2]), json.loads(els[3])
            except:
                pass
    return 0, 0, {}

def create_process_state():
    """Returns a fresh dictionary representing a single process state."""
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

def extract_functional_split_features():
    output_base_path = FEATURES_PATH / f"functional_split_ShieldFS_{N_SUB_SPLITS}"
    ransomware_logs_path = LOGS_PATH / "ransomware-irp-logs"
    
    print(f"[*] Starting Functional Splitting Attack (N_SUB={N_SUB_SPLITS})")
    print(f"[*] Total Processes per Session: {N_SUB_SPLITS * 4}")
    print(f"[*] Saving features to: {output_base_path}")

    number_folders, number_files, extension_counts = load_machine_statistics_ransomware()
    os.makedirs(output_base_path / f"tier{TIER}", exist_ok=True)

    for session_name in os.listdir(ransomware_logs_path):
        session_path = ransomware_logs_path / session_name
        
        if not session_name.endswith(".gz") or session_name not in SESSION_PID_MAP:
            continue

        print(f" -> Processing session: {session_name}")
        
        # --- CREATE FUNCTIONAL GROUPS ---
        # Each group contains N_SUB_SPLITS independent process states
        functional_groups = {
            'FILE_READ': [create_process_state() for _ in range(N_SUB_SPLITS)],
            'FILE_WRITE': [create_process_state() for _ in range(N_SUB_SPLITS)],
            'FILE_RENAME_MOVED': [create_process_state() for _ in range(N_SUB_SPLITS)],
            'DIRECTORY_LISTING': [create_process_state() for _ in range(N_SUB_SPLITS)]
        }

        # Counters to distribute operations within each group (Inner Round Robin)
        group_counters = {
            'FILE_READ': 0,
            'FILE_WRITE': 0,
            'FILE_RENAME_MOVED': 0,
            'DIRECTORY_LISTING': 0
        }

        try:
            ransomware_pid = SESSION_PID_MAP.get(session_name)
            
            with gzip.open(session_path, 'rt', encoding='utf-8') as fin:
                for line in fin:
                    try:
                        line = line.split("\t")
                        if len(line) != 23: continue

                        major_op = line[7].strip()
                        minor_op = line[8].strip()
                        file_accessed = line[22].strip()
                        process_pid = line[4].split('.')[0].strip()
                        m_m = major_op + '.' + minor_op
                        
                        if process_pid == ransomware_pid:
                            
                            # 1. Determine Functional Group
                            target_group_name = None
                            
                            if major_op in ACTIONS['FILE_READ']:
                                target_group_name = 'FILE_READ'
                            elif major_op in ACTIONS['FILE_WRITE']:
                                target_group_name = 'FILE_WRITE'
                            elif major_op in ACTIONS['FILE_RENAME_MOVED']:
                                target_group_name = 'FILE_RENAME_MOVED'
                            elif m_m in ACTIONS['DIRECTORY_LISTING']:
                                target_group_name = 'DIRECTORY_LISTING'
                            
                            # If operation isn't one of the 4 main ones, we skip it
                            if not target_group_name:
                                continue

                            # 2. Select specific sub-process within that group (Round Robin)
                            idx = group_counters[target_group_name] % N_SUB_SPLITS
                            state = functional_groups[target_group_name][idx]
                            group_counters[target_group_name] += 1
                            
                            change = True # By definition, we only entered here if it matched ACTIONS

                            # 3. Update Stats (Only for the specific action type allowed for this group)
                            # Note: A 'Reader' process will ONLY ever get Read ops, so we don't need 'if' checks here
                            # but we leave them for safety and logic clarity.
                            
                            if target_group_name == 'FILE_READ':
                                state['num_files_read'] += 1
                                
                            elif target_group_name == 'FILE_WRITE':
                                state['num_files_written'] += 1
                                state['write_entropy'] += float(line[21])
                                
                            elif target_group_name == 'FILE_RENAME_MOVED':
                                state['num_files_renamedmoved'] += 1
                                
                            elif target_group_name == 'DIRECTORY_LISTING':
                                state['num_folder_listings'] += 1

                            # 4. Update File Tracking
                            if file_accessed not in ('0.000000000000000', 'cannot get name'):
                                if file_accessed not in state['seen_files']:
                                    state['seen_files'].add(file_accessed)
                                    state['nr_files_accessed'] += 1
                                extension = os.path.splitext(file_accessed)[1]
                                state['seen_extensions'].add(extension)

                            # 5. Check TICKS
                            percentage_file_accessed = float(len(state['seen_files'])) / float(number_files) * 100
                            percentage_file_accessed = round(percentage_file_accessed, 2)

                            if state['current_tick'] < len(TICKS_EXP[TIER]) and \
                                percentage_file_accessed >= TICKS_EXP[TIER][state['current_tick']]:
                                
                                f_coverage = calculate_file_type_coverage(
                                    state['nr_files_accessed'], 
                                    state['seen_extensions'], 
                                    extension_counts
                                )
                                
                                a = float(state['num_folder_listings']) / float(number_folders)
                                b = float(state['num_files_read']) / float(number_files)
                                c = float(state['num_files_written']) / float(number_files)
                                d = float(state['num_files_renamedmoved']) / float(number_files)
                                e = state['write_entropy'] / float(state['num_files_written']) if state['num_files_written'] > 0 else 0
                                
                                state['features'][state['current_tick']].append([a, b, c, d, f_coverage, e, 'M'])

                                # Reset counters
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
                        continue

        except Exception as e:
            print(f"Error processing {session_name}: {e}")
            continue

        # --- SAVE FEATURES FOR ALL FUNCTIONAL GROUPS ---
        files_saved = 0
        for group_name, state_list in functional_groups.items():
            for state in state_list:
                for tick, feature_list in state['features'].items():
                    output_file = output_base_path / f"tier{TIER}" / f"tick{tick}.csv"
                    with open(output_file, 'a', newline='') as fp:
                        writer = csv.writer(fp)
                        writer.writerows(feature_list)
                        files_saved += 1
        
        print(f"    -> Saved {files_saved} feature batches.")

    # Generate aggregated CSV OUTSIDE the loop
    generate_all_ticks_csv(output_base_path)

if __name__ == "__main__":
    print(f"--- Functional Splitting Generator ---")
    if not os.path.exists(LOGS_PATH):
        print(f"[!] Error: Log path not found: {LOGS_PATH}")
    else:
        extract_functional_split_features()
        print("\n[+] Done. Check the 'ATTACKS' folder for results.")