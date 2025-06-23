import logging
from collections import defaultdict
import yaml
import os
import gzip
import sys
import csv
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%H:%M'
)

# Load configuration
config_path = '../../config/config.yaml'
with open(config_path, 'r') as f:
    config = yaml.safe_load(f)
time_window = config['time_window']

ransomware_logs_path = '../../datasets/raw/ShieldFS-dataset/ransomware-irp-logs/'

regular_io = 'IRP'
fast_io = 'FIO'

actions = {
    'FILE_READ': ['IRP_MJ_READ'],
    'FILE_WRITE': ['IRP_MJ_WRITE'],
    'IRP_OPEN': ['IRP_MJ_CREATE'],
    'IRP_CLOSE': ['IRP_MJ_CLOSE']
}

def date_diff_in_seconds(dt2, dt1):
    return (dt2 - dt1).total_seconds()

def rreplace(s, old, new):
    return (s[::-1].replace(old[::-1], new[::-1], 1))[::-1]

def update_feature(pid, key):
    features[pid][key] += 1
    current_time[pid] = parsed_time

def get_ransomware_pid(ransomware_log):
    try:
        with open('ransomware_pids/' + ransomware_log, 'r') as fp:
            csv_reader = csv.reader(fp)
            headings = next(csv_reader)
            first_line = next(csv_reader)
            return first_line[0].strip()
    except Exception as e:
        logging.error(f"Failed to read ransomware PID from {ransomware_log}: {e}")
        return None

for session_name in os.listdir(ransomware_logs_path):
    session_path = os.path.join(ransomware_logs_path, session_name)
    if not os.path.isfile(session_path) or not session_path.endswith('.gz'):
        continue

    logging.info(f"Processing ransomware session: {session_name}")

    features = defaultdict(lambda: {'READ': 0, 'WRITE': 0, 'OPEN': 0, 'CLOSE': 0,
                                    'FAST_READ': 0, 'FAST_WRITE': 0, 'FAST_CLOSE': 0, 'FAST_OPEN': 0})
    global_features = []
    previous_time = {}
    current_time = {}

    # You can switch to dynamic pid loading here if needed:
    # ransomware_pid = get_ransomware_pid(session_name + '.csv')
    ransomware_pid = '2616'
    logging.info(f"Using ransomware PID: {ransomware_pid}")

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
                    logging.error(f"Parsing error in {session_name} line {line_num}: {e}")
                    continue

                previous_time.setdefault(process_pid, parsed_time)
                current_time[process_pid] = parsed_time

                if operation_type == regular_io:
                    if major_op in actions['FILE_READ']:
                        update_feature(process_pid, 'READ')
                    elif major_op in actions['FILE_WRITE']:
                        update_feature(process_pid, 'WRITE')
                    elif major_op in actions['IRP_OPEN']:
                        update_feature(process_pid, 'OPEN')
                    elif major_op in actions['IRP_CLOSE']:
                        update_feature(process_pid, 'CLOSE')
                elif operation_type == fast_io:
                    if major_op in actions['FILE_READ']:
                        update_feature(process_pid, 'FAST_READ')
                    elif major_op in actions['FILE_WRITE']:
                        update_feature(process_pid, 'FAST_WRITE')
                    elif major_op in actions['IRP_CLOSE']:
                        update_feature(process_pid, 'FAST_CLOSE')
                    elif major_op in actions['IRP_OPEN']:
                        update_feature(process_pid, 'FAST_OPEN')

                if date_diff_in_seconds(current_time[process_pid], previous_time[process_pid]) >= time_window:
                    counts = features[process_pid]
                    if any(counts[feat] != 0 for feat in counts):
                        global_features.append([
                            counts['READ'], counts['WRITE'], counts['OPEN'], counts['CLOSE'],
                            counts['FAST_READ'], counts['FAST_WRITE'], counts['FAST_CLOSE'], counts['FAST_OPEN'],
                            'M'
                        ])
                    previous_time[process_pid] = current_time[process_pid]
                    for key in counts:
                        counts[key] = 0

        output_filename = f'../../datasets/features/RWGuard/ransomware_rwguard_features_{time_window}sec.csv'
        with open(output_filename, 'a', newline='') as fp:
            writer = csv.writer(fp)
            writer.writerows(global_features)

        logging.info(f"Finished processing ransomware session {session_name}")

    except OSError as e:
        logging.error(f"Error opening/reading gzip file {session_path}: {e}")

    except Exception as e:
        logging.error(f"Unexpected error in session {session_name}: {e}")
