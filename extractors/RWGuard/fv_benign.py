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

BENIGN_LOGS_PATH = BASE_DIR / 'datasets' / 'raw' / 'ShieldFS-dataset' / 'benign-irp-logs'

REGULAR_IO = 'IRP'
FAST_IO = 'FIO'

ACTIONS = {
    'FILE_READ': ['IRP_MJ_READ'],
    'FILE_WRITE': ['IRP_MJ_WRITE'],
    'IRP_OPEN': ['IRP_MJ_CREATE'],
    'IRP_CLOSE': ['IRP_MJ_CLOSE']
}

def date_diff_in_seconds(dt2, dt1):
    return (dt2 - dt1).total_seconds()

def rreplace(s, old, new):
    return (s[::-1].replace(old[::-1], new[::-1], 1))[::-1]

def extract_features():
    for machine_name in os.listdir(BENIGN_LOGS_PATH):
        machine_path = os.path.join(BENIGN_LOGS_PATH, machine_name)
        if not os.path.isdir(machine_path):
            continue

        print(f"The machine being processed is: {machine_name}")

        session_base_path = os.path.join(BENIGN_LOGS_PATH, machine_name)
        for session_name in os.listdir(session_base_path):

            session_folder_path = os.path.join(session_base_path, session_name)
            if not os.path.isdir(session_folder_path):
                continue

            print(f"Processing session: {session_name}")

            features = defaultdict(lambda: {'READ': 0, 'WRITE': 0, 'OPEN': 0, 'CLOSE': 0,
                                            'FAST_READ': 0, 'FAST_WRITE': 0,  'FAST_OPEN': 0, 'FAST_CLOSE': 0})
            global_features = []
            previous_time = {}
            current_time = {}

            def update_feature(pid, feature_key):
                features[pid][feature_key] += 1
                current_time[pid] = parsed_time
            
            output_dir = BASE_DIR / 'datasets' / 'features' / 'RWGuard'
            output_dir.mkdir(parents=True, exist_ok=True)
            output_filename = output_dir / f'benign_rwguard_features_{TIME_WINDOW}sec.csv'

            try:
                for inFile in os.listdir(session_folder_path):
                    if not inFile.endswith('.gz'):
                        continue

                    file_to_process = os.path.join(session_folder_path, inFile)
                    try:
                        with gzip.open(file_to_process, 'rt', encoding='utf-8', errors='ignore') as fin:
                            for line_num, line in enumerate(fin, 1):
                                line = line.strip().split('\t')
                                if len(line) != 23:
                                    continue

                                try:
                                    major_op = line[7].strip()
                                    operation_type = line[0].strip()
                                    process_pid = line[4].split('.')[0].strip()
                                    post_operation_time = rreplace(line[3].strip(), ':', '.')

                                    parsed_time = datetime.strptime(post_operation_time, '%H:%M:%S.%f')
                                except Exception as e:
                                    print(f"Parsing error in {inFile} line {line_num}: {e}")
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
                                            counts['FAST_READ'], counts['FAST_WRITE'],  counts['FAST_OPEN'], counts['FAST_CLOSE'],
                                            'N'
                                        ])
                                    previous_time[process_pid] = current_time[process_pid]
                                    for key in counts:
                                        counts[key] = 0

                        if global_features:
                            with open(output_filename, 'a', newline='') as fp:
                                writer = csv.writer(fp)
                                writer.writerows(global_features)
                            global_features.clear()

                            
                    except OSError as e:
                        print(f"Error opening/reading gzip file {file_to_process}: {e}")



                print(f'Finished processing session {session_name}')
            except Exception as e:
                print(f"Unexpected error processing session {session_name}: {e}")


# if __name__ == "__main__":
#     extract_features()
