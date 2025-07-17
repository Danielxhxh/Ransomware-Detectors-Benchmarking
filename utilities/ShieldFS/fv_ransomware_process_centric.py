from collections import defaultdict
import os
import gzip
import json
import csv
from scripts.utils.load_config import config, BASE_DIR

LOGS_PATH = BASE_DIR / 'data' / 'ShieldFS-dataset'
FEATURES_PATH = BASE_DIR / 'datasets' / 'ShieldFS' / 'process_centric' / 'ransomware'

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


SESSION_PID_MAP = {
    '480bd1ecb1b969e6677c1e11a30cd985e4244e5de04956e2dbb0e6b97c42027e.gz': '2616',
    '09c278fc0ae3a36170a71e65bba9f92da086fca941ba93051811bf16c6b67f64.gz': '2060',
    '0d6fb25cde440df0d2b6a676e86b23c47c298f60f8ec461805cc4cd77dd9f730.gz': '3680',
    'c80d611b38c6ea23cf9d564111a24f245f48df48a5341da896912054dd7d9529.gz': '3684'
}

def load_machine_statistics():
    statistics_file = BASE_DIR / 'models' / 'ShieldFS' / 'statistics' / 'machine_statistics_virtual.txt'
    with open(statistics_file, 'r') as fp:
        for ln in fp:
            try:
                els = ln.split('\t')
                return int(els[1]), int(els[2]), json.loads(els[3])
            except:
                pass

def calculate_file_type_coverage(total_files_accessed, currently_seen_extensions, extension_counts_dict):
    sum_counts = sum(extension_counts_dict.get(ext, 0) for ext in currently_seen_extensions)
    return float(total_files_accessed) / float(sum_counts) if sum_counts != 0 else 0

ransomware_logs_path = LOGS_PATH / "ransomware-irp-logs"

number_folders, number_files, extension_counts = load_machine_statistics()

for session_name in os.listdir(ransomware_logs_path):
    print("The ransomware log is: ", session_name)

    session_path = ransomware_logs_path / session_name
    current_tick = 0
    features = defaultdict(list)
    seen_files = set()
    seen_extensions = set()
    num_folder_listings = 0
    num_files_read = 0
    num_files_written = 0
    num_files_renamedmoved = 0
    write_entropy = 0.0
    nr_files_accessed = 0

    try:
        if session_name.endswith(".gz"):
            ransomware_pid = SESSION_PID_MAP.get(session_name)
            with gzip.open(session_path, 'r') as fin:
                for line in fin:
                    try:
                        line = line.decode("utf-8").split("\t")
                        if len(line) != 23:
                            continue

                        major_op = line[7].strip()
                        minor_op = line[8].strip()
                        file_accessed = line[22].strip()
                        process_pid = line[4].split('.')[0].strip()
                        m_m = major_op + '.' + minor_op
                        change = False

                        if process_pid == ransomware_pid:
                            if major_op in ACTIONS['FILE_READ']:
                                num_files_read += 1
                                change = True

                            if major_op in ACTIONS['FILE_WRITE']:
                                num_files_written += 1
                                write_entropy += float(line[21])
                                change = True

                            if major_op in ACTIONS['FILE_RENAME_MOVED']:
                                num_files_renamedmoved += 1
                                change = True

                            if m_m in ACTIONS['DIRECTORY_LISTING']:
                                num_folder_listings += 1
                                change = True

                            if change and file_accessed not in ('0.000000000000000', 'cannot get name'):
                                if file_accessed not in seen_files:
                                    seen_files.add(file_accessed)
                                    nr_files_accessed += 1

                                _, sep, ext = file_accessed.rpartition('.')
                                extension = f'.{ext}' if sep else ''
                                seen_extensions.add(extension)

                            percentage_file_accessed = float(len(seen_files)) / float(number_files) * 100
                            percentage_file_accessed = round(percentage_file_accessed, 2)

                            if change and current_tick < len(TICKS_EXP[tier]) and percentage_file_accessed >= TICKS_EXP[tier][current_tick]:
                                f_coverage = calculate_file_type_coverage(nr_files_accessed, seen_extensions, extension_counts)
                                a = float(num_folder_listings) / float(number_folders)
                                b = float(num_files_read) / float(number_files)
                                c = float(num_files_written) / float(number_files)
                                d = float(num_files_renamedmoved) / float(number_files)
                                e = write_entropy / float(num_files_written) if num_files_written > 0 else 0
                                features[current_tick].append([a, b, c, d, f_coverage, e])

                                num_folder_listings = 0
                                num_files_read = 0
                                num_files_written = 0
                                num_files_renamedmoved = 0
                                write_entropy = 0.0
                                nr_files_accessed = 0
                                seen_extensions.clear()
                                seen_files.clear()

                                current_tick += 1
                    except UnicodeDecodeError:
                        continue
    except Exception:
        continue

    output_dir = FEATURES_PATH / f"tier{tier}"
    os.makedirs(output_dir, exist_ok=True)

    for tick, feature_list in features.items():
        output_file = output_dir / f"tick{tick}.csv"
        with open(output_file, 'a', newline='') as fp:
            writer = csv.writer(fp)
            writer.writerows(feature_list)

    print('Finished Ransomware Session', session_name)
