import os
import gzip
import sys
import json
import csv
from scripts.utils.load_config import config, BASE_DIR

LOGS_PATH = BASE_DIR / 'data' / 'ShieldFS-dataset'
FEATURES_PATH = BASE_DIR / 'datasets' / 'ShieldFS' / 'system_centric' 

ACTIONS = {
    'FILE_READ': ['IRP_MJ_READ'],
    'FILE_WRITE': ['IRP_MJ_WRITE'],
    'FILE_RENAME_MOVED': ['IRP_MJ_SET_INFORMATION'],
    'DIRECTORY_LISTING': ['IRP_MJ_DIRECTORY_CONTROL.IRP_MN_QUERY_DIRECTORY'],
}

def load_machine_statistics(machine):
    statistics_file = BASE_DIR / 'models' / 'ShieldFS' / 'statistics' /'machine_statistics.txt'
    with open(statistics_file, 'r') as fp:
        for ln in fp:
            try:
                els = ln.split('\t')
                if els[0] == machine:
                    return int(els[1]), int(els[2]), json.loads(els[3])
            except:
                pass

def calculate_file_type_coverage(total_files_accessed, currently_seen_extensions, extension_counts_dict):
    sum_counts = 0
    for ext in currently_seen_extensions:
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

    number_folders, number_files, extension_counts = load_machine_statistics(machine_name)

    print(f"Processing machine: {machine_name}")

    for session_name in os.listdir(machine_path):
        session_folder_path = machine_path / session_name
        if not session_folder_path.is_dir():
            continue
        
        print(f"Processing session: {session_name}")
        
        # features = dict()
        num_folder_listings = 0
        num_files_read = 0
        num_files_written = 0
        num_files_renamedmoved = 0
        write_entropy = 0.0
        seen_ext = set()
        seen_files = set()
        nr_files_accessed = 0

        for inFile in os.listdir(session_folder_path):
            try:
                if inFile.endswith(".gz"):
                    filetoProcess = os.path.join(session_folder_path, inFile)
                    with gzip.open(filetoProcess, 'r') as fin:
                        for line in fin:
                            try:
                                convert = line.decode("utf-8")
                                line = convert.split("\t")
                                if len(line) == 23:
                                    major_op = line[7].strip()
                                    minor_op = line[8].strip()
                                    file_accessed = line[22].strip()
                                    m_m = major_op+'.'+minor_op
                                    change = False

                                    if major_op in ACTIONS['FILE_READ']:
                                        num_files_read = num_files_read + 1
                                        change = True

                                    if major_op in ACTIONS['FILE_WRITE']:
                                        num_files_written = num_files_written + 1
                                        write_entropy = write_entropy + float(line[21])
                                        change = True

                                    if major_op in ACTIONS['FILE_RENAME_MOVED']:
                                        num_files_renamedmoved = num_files_renamedmoved + 1
                                        change = True

                                    if m_m in ACTIONS['DIRECTORY_LISTING']:
                                        num_folder_listings = num_folder_listings + 1
                                        change = True

                                    if change and file_accessed not in ('0.000000000000000', 'cannot get name'):
                                        if file_accessed not in seen_files:
                                            seen_files.add(file_accessed)
                                            nr_files_accessed += 1
                                        parts = file_accessed.split('.')
                                        if len(parts) == 1:
                                            seen_ext.add('')
                                        elif len(parts) == 2:
                                            seen_ext.add('.' + parts[1])

                            except UnicodeDecodeError:
                                continue
            except Exception as e:
                continue

        # Compute features after full session
        f_coverage = calculate_file_type_coverage(nr_files_accessed, seen_ext, extension_counts)
        a = float(num_folder_listings) / float(number_folders)
        b = float(num_files_read) / float(number_files)
        c = float(num_files_written) / float(number_files)
        d = float(num_files_renamedmoved) / float(number_files)
        e = write_entropy / float(num_files_written) if num_files_written > 0 else 0
        feature_vector = [a, b, c, d, f_coverage, e]

        # Write one row per session
        output_file = FEATURES_PATH / "benign_shieldfs_features.csv"
        with output_file.open('a', newline='') as fp:
            wr = csv.writer(fp)
            wr.writerow(feature_vector)

        print('Finished session', session_name)