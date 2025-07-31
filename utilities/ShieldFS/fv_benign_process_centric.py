from collections import defaultdict
import os
import gzip
import sys
import json
import csv
from scripts.utils.load_config import config, BASE_DIR

LOGS_PATH = BASE_DIR / 'data' / 'ShieldFS-dataset'
FEATURES_PATH = BASE_DIR / 'datasets' / 'ShieldFS' / 'process_centric' / 'benign'

tier = 5

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

def load_machine_statistics(machine):
    statistics_file = BASE_DIR / 'utilities' / 'ShieldFS' / 'statistics'/ 'machine_statistics.txt'
    with open(statistics_file, 'r') as fp:
        for ln in fp:
            try:
                els = ln.split('\t')
                if els[0] == machine:
                    return int(els[1]), int(els[2]), json.loads(els[3])
            except:
                pass

def calculate_file_type_coverage(total_files_accessed, currently_seen_extension, extension_counts_dict):
    sum_counts = 0
    for ext in currently_seen_extension:
        if ext in extension_counts.keys():
            sum_counts = sum_counts + extension_counts_dict[ext]
    if sum_counts == 0:
        return 0
    else:
        return float(total_files_accessed)/float(sum_counts)

benign_logs_path = LOGS_PATH / "benign-irp-logs"

for machine_name in os.listdir(benign_logs_path):
    machine_path = benign_logs_path / machine_name
    if not machine_path.is_dir():
        continue

    print(f"Processing machine: {machine_name}")

    number_folders, number_files, extension_counts = load_machine_statistics(machine_name)

    for session_name in os.listdir(machine_path):
        session_folder_path = machine_path / session_name
        if not session_folder_path.is_dir():
            continue

        print(f"Processing session: {session_name}")

        features = defaultdict(list)

        # Initialize per-process dicts 
        num_folder_listings = defaultdict(int)
        num_files_read = defaultdict(int)
        num_files_written = defaultdict(int)
        num_files_renamedmoved = defaultdict(int)
        write_entropy = defaultdict(float)
        seen_extensions = defaultdict(set)
        seen_files = defaultdict(set)
        nr_files_accessed = defaultdict(int)
        process_ticks = defaultdict(int)
        percentage_file_accessed = defaultdict(float)

        for inFile in os.listdir(session_folder_path):
            if inFile.endswith(".gz"):
                filetoProcess = session_folder_path / inFile
                try:
                    with gzip.open(filetoProcess, 'rt', encoding='utf-8') as fin:
                        for line in fin:
                            line = line.strip().split('\t')
                            if len(line) != 23:
                                continue

                            major_op = line[7].strip()
                            minor_op = line[8].strip()
                            process_pid = line[4].split('.')[0].strip()
                            file_accessed = line[22].strip()
                            m_m = f"{major_op}.{minor_op}"
                            change = False

                            if major_op in ACTIONS['FILE_READ']:
                                num_files_read[process_pid] += 1
                                change = True

                            if major_op in ACTIONS['FILE_WRITE']:
                                num_files_written[process_pid] += 1
                                write_entropy[process_pid] += float(line[21])
                                change = True

                            if major_op in ACTIONS['FILE_RENAME_MOVED']:
                                num_files_renamedmoved[process_pid] += 1
                                change = True

                            if m_m in ACTIONS['DIRECTORY_LISTING']:
                                num_folder_listings[process_pid] += 1
                                change = True

                            if change and file_accessed not in ('0.000000000000000', 'cannot get name'):
                                if file_accessed not in seen_files[process_pid]:
                                    seen_files[process_pid].add(file_accessed)
                                    nr_files_accessed[process_pid] += 1

                                # Extract file extension
                                _, sep, ext = file_accessed.rpartition('.')
                                extension = f'.{ext}' if sep else ''
                                seen_extensions[process_pid].add(extension)

                                # Update percentage file accessed
                                p_f = float(len(seen_files[process_pid])) / number_files * 100
                                percentage_file_accessed[process_pid] = round(p_f, 2)
                            
                            # Check if current process tick threshold met, and then if it's in the current bounds
                            current_tick = process_ticks[process_pid]
                            if change and current_tick < len(TICKS_EXP[tier]) and percentage_file_accessed[process_pid] >= TICKS_EXP[tier][current_tick]:
                                f_coverage = calculate_file_type_coverage(nr_files_accessed[process_pid], seen_extensions[process_pid], extension_counts)
                                a = float(num_folder_listings[process_pid]) / float(number_folders)
                                b = float(num_files_read[process_pid]) / float(number_files)
                                c = float(num_files_written[process_pid]) / float(number_files)
                                d = float(num_files_renamedmoved[process_pid]) / float(number_files)
                                e = (write_entropy[process_pid] / float(num_files_written[process_pid])) if num_files_written[process_pid] > 0 else 0

                                features[current_tick].append([a, b, c, d, f_coverage, e])

                                # Reset counters for next tick
                                num_folder_listings[process_pid] = 0
                                num_files_read[process_pid] = 0
                                num_files_written[process_pid] = 0
                                num_files_renamedmoved[process_pid] = 0
                                write_entropy[process_pid] = 0.0
                                nr_files_accessed[process_pid] = 0
                                seen_extensions[process_pid].clear()
                                seen_files[process_pid].clear()
                                percentage_file_accessed[process_pid] = 0

                                process_ticks[process_pid] += 1

                except Exception as e:
                    print(f"Error processing file {filetoProcess}: {e}")

        # Write features per tick to disk
        output_dir = FEATURES_PATH / f"tier{tier}"
        os.makedirs(output_dir, exist_ok=True)

        for tick, feature_list in features.items():
            output_file = output_dir / f"tick{tick}.csv"
            with open(output_file, 'a', newline='') as fp:
                writer = csv.writer(fp)
                writer.writerows(feature_list)

        print(f'Finished session {session_name}')
