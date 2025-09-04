from datetime import datetime
import os
import gzip
import csv
import json
from typing import Optional, Tuple
import numpy as np
from collections import defaultdict
from dataclasses import dataclass, field
from sklearn import metrics
import joblib
from scripts.utils.load_config import BASE_DIR
from scripts.utils.calculate_hash import calculate_hash

FEATURES_PATH = BASE_DIR / 'datasets' / 'Redemption'
LOGS_PATH = BASE_DIR / 'data' / 'ShieldFS-dataset' 
SAVED_MODELS_PATH = BASE_DIR / 'saved_models'

ACTIONS = {
    'FILE_READ': ['IRP_MJ_READ'],
    'FILE_WRITE': ['IRP_MJ_WRITE'],
    'FILE_RENAME_MOVED': ['IRP_MJ_SET_INFORMATION'],
    'DIRECTORY_LISTING': ['IRP_MJ_DIRECTORY_CONTROL.IRP_MN_QUERY_DIRECTORY'],
}

EXTENSION_CATEGORY = {
    "office_doc": {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt"},
    "pdf": {".pdf"},
    "text": {".txt", ".rtf"},
    "image": {".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tiff", ".svg", ".webp"},
    "audio": {".mp3", ".wav", ".flac", ".aac", ".ogg"},
    "video": {".mp4", ".avi", ".mov", ".mkv", ".wmv"},
    "archive": {".zip", ".rar", ".7z", ".tar", ".gz"},
    "binary": {".exe", ".dll", ".bin", ".manifest", ".vdf", ".nls"},
    "code": {".py", ".c", ".cpp", ".java", ".js", ".cs", ".html", ".css"},
    "config": {".log", ".ini", ".cfg", ".json", ".xml"},
}
EXTENSION_LOOKUP = {ext: category for category, exts in EXTENSION_CATEGORY.items() for ext in exts}


# Redemption feature weights (from paper)
FEATURE_WEIGHTS = {
    "entropy_ratio": 0.9,
    "content_overwrite": 1.0,
    "delete_operation": 0.6,
    "dir_traversal": 1.0,
    "convert_type": 0.7,
    "access_frequency": 1.0,
}
THRESHOLD = 0.12  # MSC threshold

@dataclass
class FileActivity:
    last_read_entropy: float = None
    last_write_entropy: float = None
    entropy_ratio: float = None

@dataclass
class ProcessProfile:
    # r1
    files: dict = field(default_factory=dict)   # {filename: FileActivity}
    # r2 TODO

    # r3
    delete_operation: int = 0
    # r4
    dir_writes = defaultdict(set)  # path -> set of unique files written
    dir_traversals: Optional[float] = None
    # r5
    file_classes: set = field(default_factory=set)        # track unique classes
    convert_type: int = 0 
    # r6
    last_write: Tuple[Optional[datetime], str] = (None, "")  # (timestamp,filename)
    elapsed_time: Optional[float] = None
    access_frequency: Optional[float] = None


class Redemption:
    def __init__(self):
        self.weights = FEATURE_WEIGHTS
        self.threshold = THRESHOLD

    @staticmethod
    def _get_file_class(filename):
        _, ext = os.path.splitext(filename.lower())
        return EXTENSION_LOOKUP.get(ext, "other")
    
    @staticmethod
    def _date_diff_in_seconds(dt2, dt1) -> Optional[float]:
        delta = (dt2 - dt1).total_seconds()
        return delta if delta >= 0 else None
    
    @staticmethod
    def _rreplace(s, old, new):
        return (s[::-1].replace(old[::-1], new[::-1], 1))[::-1]
    
    @staticmethod
    def _safe_float(value: str) -> Optional[float]:
        try:
            return float(value.strip())
        except ValueError:
            return None

    def _update_access_frequency(self, process: ProcessProfile, parsed_time: datetime, file_accessed: str):
        if process.last_write[1] == file_accessed:
            return  # same file → skip

        if process.last_write[0] is not None:
            process.elapsed_time = self._date_diff_in_seconds(parsed_time, process.last_write[0])
            if process.elapsed_time is not None:
                # Maximum time gap considered "fast access".
                # If two writes happen within <= delta_cap, access_frequency ≈ 1 (high frequency).
                # If delta >= delta_cap, access_frequency → 0 (low frequency).
                delta_cap = 0.1  # seconds
                process.access_frequency = 1 - min(process.elapsed_time / delta_cap, 1)
            else:
                process.access_frequency = None
        else:
            process.elapsed_time = None
            process.access_frequency = None

        process.last_write = (parsed_time, file_accessed)

    @staticmethod
    def _update_entropy_ratio(file_activity: FileActivity):
        if file_activity.last_read_entropy is None or file_activity.last_write_entropy is None:
            return

        if file_activity.last_write_entropy > file_activity.last_read_entropy:
            file_activity.entropy_ratio = (
                (file_activity.last_write_entropy - file_activity.last_read_entropy)
                / file_activity.last_write_entropy
            )
        else:
            file_activity.entropy_ratio = 0.0

        
    def extract_benign_features(self):
        features_path = FEATURES_PATH / "benign"
        benign_logs_path = LOGS_PATH / "benign-irp-logs"

        for machine_name in os.listdir(benign_logs_path):
            machine_path = benign_logs_path / machine_name
            if not machine_path.is_dir():
                continue

            print(f"Processing machine: {machine_name}")

            for session_name in os.listdir(machine_path):
                session_folder_path = machine_path / session_name
                if not session_folder_path.is_dir():
                    continue

                print(f"Processing session: {session_name}")


                process_state = defaultdict(ProcessProfile)

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
                                    post_time = self._rreplace(line[3].strip(), ':', '.')
                                    parsed_time = datetime.strptime(post_time, '%H:%M:%S.%f')
                                    
                                    file_accessed = line[22].strip()
                                    m_m = f"{major_op}.{minor_op}"

                                    # Skip invalid names
                                    if file_accessed in ('0.000000000000000', 'cannot get name'):
                                        continue

                                    # Get the process profile
                                    process = process_state[process_pid]

                                    # Ensure we have a FileActivity for this file
                                    if file_accessed not in process.files:
                                        process.files[file_accessed] = FileActivity()

                                    # Update based on operation
                                    if major_op in ACTIONS['FILE_READ']:
                                        # 1. Entropy update
                                        entropy_val = self._safe_float(line[21])
                                        process.files[file_accessed].last_read_entropy = entropy_val

                                    elif major_op in ACTIONS['FILE_WRITE']:
                                        # 1. Entropy update
                                        entropy_val = self._safe_float(line[21])
                                        process.files[file_accessed].last_write_entropy = entropy_val

                                        # 2. File class tracking
                                        file_class = self._get_file_class(file_accessed)
                                        process.file_classes.add(file_class)
                                        if len(process.file_classes) > 1:
                                            process.convert_type = 1

                                        # 3. Access frequency (elapsed time)
                                        self._update_access_frequency(process, parsed_time, file_accessed)

                                        # 4. Entropy ratio
                                        self._update_entropy_ratio(process.files[file_accessed])

                                        # 5. Used to check directory traversals
                                        dir_path, filename = os.path.split(file_accessed.replace("\\", "/"))
                                        process.dir_writes[dir_path].add(filename)

                                        Np = len(process.dir_writes[dir_path])  # unique files in this path
                                        N_MAX = 100  # normalization cap (tunable)

                                        process.dir_traversals = min(Np / N_MAX, 1.0)

                                    elif major_op in ACTIONS['FILE_RENAME_MOVED']:
                                        # Could be delete/rename
                                        process.delete_operation += 1


                        except Exception as e:
                            print(f"Error processing file {filetoProcess}: {e}")

                # # Write features per tick to disk
                # output_dir = features_path / f"tier{TIER}"
                # os.makedirs(output_dir, exist_ok=True)

                # for tick, feature_list in features.items():
                #     output_file = output_dir / f"tick{tick}.csv"
                #     with open(output_file, 'a', newline='') as fp:
                #         writer = csv.writer(fp)
                #         writer.writerows(feature_list)
                print(f'Finished session {session_name}')

if __name__ == "__main__":
    redemption = Redemption()
    redemption.extract_benign_features()
