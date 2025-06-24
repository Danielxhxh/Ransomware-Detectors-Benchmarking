from collections import defaultdict
import yaml
import os
import gzip
import sys
import csv
from datetime import datetime
from pathlib import Path
from scripts.utils.load_config import config, BASE_DIR

TIME_WINDOW = config['time_window'] 
RANSOMWARE_LOGS_PATH = BASE_DIR / 'datasets' / 'raw' / 'ShieldFS-dataset' / 'ransomware-irp-logs'

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

def date_diff_in_seconds(dt2, dt1):
    return (dt2 - dt1).total_seconds()

def rreplace(s, old, new):
    return (s[::-1].replace(old[::-1], new[::-1], 1))[::-1]



def get_ransomware_pid(ransomware_log):
    try:
        with open('ransomware_pids/' + ransomware_log, 'r') as fp:
            csv_reader = csv.reader(fp)
            headings = next(csv_reader)
            first_line = next(csv_reader)
            return first_line[0].strip()
    except Exception as e:
        print(f"Failed to read ransomware PID from {ransomware_log}: {e}")
        return None

def extract_features():
    for session_name in os.listdir(RANSOMWARE_LOGS_PATH):
        session_path = os.path.join(RANSOMWARE_LOGS_PATH, session_name)
        if not os.path.isfile(session_path) or not session_path.endswith('.gz'):
            continue

        print(f"Processing ransomware session: {session_name}")

        features = defaultdict(lambda: {'READ': 0, 'WRITE': 0, 'OPEN': 0, 'CLOSE': 0,
                                        'FAST_READ': 0, 'FAST_WRITE': 0, 'FAST_OPEN': 0, 'FAST_CLOSE': 0})
        global_features = []
        previous_time = {}
        current_time = {}
                           
        def update_feature(pid, key):
            features[pid][key] += 1
            current_time[pid] = parsed_time

        # You can switch to dynamic pid loading here if needed:
        # ransomware_pid = get_ransomware_pid(session_name + '.csv')
        ransomware_pid = SESSION_PID_MAP.get(session_name)
        print(f"Using ransomware PID: {ransomware_pid}")

        try:
            with gzip.open(session_path, 'rt', encoding='utf-8', errors='ignore') as fin:
                # Skip headers
                next(fin)
                next(fin)

                for line_num, line in enumerate(fin, 3):  # start counting from line 3
                    line = line.strip().split('\t')
                    if len(line) != 23:
                        continue

                    try:
                        major_op = line[7].strip()
                        operation_type = line[0].strip()
                        process_pid = line[4].split('.')[0].strip()
                        post_operation_time = rreplace(line[3].strip(), ':', '.')

                        if process_pid != ransomware_pid:
                            continue

                        parsed_time = datetime.strptime(post_operation_time, '%H:%M:%S.%f')
                    except Exception as e:
                        print(f"Parsing error in {session_name} line {line_num}: {e}")
                        continue

                    previous_time.setdefault(process_pid, parsed_time)
                    current_time[process_pid] = parsed_time
 
                    
                    if operation_type == REGULAR_IO:
                        if major_op in ACTIONS['FILE_READ']:
                            update_feature(process_pid, 'READ')
                        elif major_op in ACTIONS['FILE_WRITE']:
                            update_feature(process_pid, 'WRITE')
                        elif major_op in ACTIONS['IRP_OPEN']:
                            update_feature(process_pid, 'OPEN')
                        elif major_op in ACTIONS['IRP_CLOSE']:
                            update_feature(process_pid, 'CLOSE')
                    elif operation_type == FAST_IO:
                        if major_op in ACTIONS['FILE_READ']:
                            update_feature(process_pid, 'FAST_READ')
                        elif major_op in ACTIONS['FILE_WRITE']:
                            update_feature(process_pid, 'FAST_WRITE')
                        elif major_op in ACTIONS['IRP_OPEN']:
                            update_feature(process_pid, 'FAST_OPEN')
                        elif major_op in ACTIONS['IRP_CLOSE']:
                            update_feature(process_pid, 'FAST_CLOSE')
                    if date_diff_in_seconds(current_time[process_pid], previous_time[process_pid]) >= TIME_WINDOW:
                        counts = features[process_pid]
                        if any(counts[feat] != 0 for feat in counts):
                            global_features.append([
                                counts['READ'], counts['WRITE'], counts['OPEN'], counts['CLOSE'],
                                counts['FAST_READ'], counts['FAST_WRITE'],counts['FAST_OPEN'], counts['FAST_CLOSE'],
                                'M'
                            ])
                        previous_time[process_pid] = current_time[process_pid]
                        for key in counts:
                            counts[key] = 0

            output_dir = BASE_DIR / 'datasets' / 'features' / 'RWGuard'
            output_dir.mkdir(parents=True, exist_ok=True)
            output_filename = output_dir / f'ransomware_rwguard_features_{TIME_WINDOW}sec.csv'
            with open(output_filename, 'a', newline='') as fp:
                writer = csv.writer(fp)
                writer.writerows(global_features)
            
            print(f"Finished processing ransomware session {session_name}")

        except OSError as e:
            print(f"Error opening/reading gzip file {session_path}: {e}")

        except Exception as e:
            print(f"Unexpected error in session {session_name}: {e}")

# if __name__ == "__main__":
#     extract_features()
