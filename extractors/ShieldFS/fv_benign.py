import os
import gzip
import sys
import json
import csv

benign_path = '../../datasets/ShieldFS-dataset/benign-irp-logs/'

machine_name = sys.argv[1]
tier = int(sys.argv[2])
part = sys.argv[3]

actions = {
    'FILE_READ': ['IRP_MJ_READ'],
    'FILE_WRITE': ['IRP_MJ_WRITE'],
    'FILE_RENAME_MOVED': ['IRP_MJ_SET_INFORMATION'],
    'DIRECTORY_LISTING': ['IRP_MJ_DIRECTORY_CONTROL.IRP_MN_QUERY_DIRECTORY'],
}

ticks_exp = {
    1: [0.1, 0.13, 0.17, 0.22, 0.29, 0.37, 0.48, 0.63, 0.82, 1, 1.38,
        1.79, 2.3, 3, 3.9, 5, 6.65, 8.65, 11.25, 14.65, 19, 24.7, 32.1, 41, 54, 70.5, 91, 100],
    2: [0.13,  0.22, 0.37,  0.63, 1, 1.79, 3, 5, 8.65, 14.65, 24.7, 41, 70.5, 100],
    3: [0.17, 0.37, 0.82, 1.79, 3.9, 8.65, 19, 41, 100],
    4: [0.22, 0.63, 1.79, 5, 14.65, 41, 100],
    5: [0.29, 1, 3.9, 14.65, 54, 100],
    6: [0.37, 1.79, 8.65, 41, 100],
    7: [0.48, 3, 19, 100],
    8: [0.63, 5, 41, 100],
    9: [0.82, 8.65, 100],
    10: [1, 14.65, 100],
    11: [1.38, 24.7, 100],
    12: [1.79, 41, 100],
    13: [2.3, 70.5, 100],
    14: [3, 100],
    15: [3.9, 100],
    16: [5, 100],
    17: [6.65, 100],
    18: [8.65, 100],
    19: [11.25, 100],
    20: [14.65, 100],
    21: [19, 100],
    22: [24.7, 100],
    23: [32.1, 100],
    24: [41, 100],
    25: [54, 100],
    26: [70.5, 100],
    27: [91, 100],
    28: [100]
}


print("The machine being processed is:", machine_name)


def load_machine_statistics(machine):
    with open('statistics_summary_new.txt', 'r') as fp:
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


number_folders, number_files, extension_counts = load_machine_statistics(machine_name)

p = benign_path+machine_name+'/'+part

for session_folder_name in os.listdir(p):
    print(session_folder_name)
    if os.path.isdir(os.path.join(p, session_folder_name)):
        session_folder_path = os.path.join(p, session_folder_name)

        current_tick = 0
        features = dict()

        num_folder_listings = 0
        num_files_read = 0
        num_files_written = 0
        num_files_renamedmoved = 0
        write_entropy = 0
        seen_ext = []
        nr_files_accessed = 0
        percentage_file_accessed = 0.0
        seen_files = []

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

                                    if major_op in actions['FILE_READ']:
                                        num_files_read = num_files_read + 1
                                        change = True

                                    if major_op in actions['FILE_WRITE']:
                                        num_files_written = num_files_written + 1
                                        write_entropy = write_entropy + float(line[21])
                                        change = True

                                    if major_op in actions['FILE_RENAME_MOVED']:
                                        num_files_renamedmoved = num_files_renamedmoved + 1
                                        change = True

                                    if m_m in actions['DIRECTORY_LISTING']:
                                        num_folder_listings = num_folder_listings + 1
                                        change = True

                                    if file_accessed is not '0.000000000000000' and file_accessed is not 'cannot get name':
                                        if change is True:
                                            al = file_accessed.split('.')
                                            if file_accessed not in seen_files:
                                                seen_files.append(file_accessed)
                                                nr_files_accessed = nr_files_accessed + 1

                                            if len(al) == 1:
                                                if '' not in seen_ext:
                                                    seen_ext.append('')
                                            elif len(al) == 2:
                                                if '.'+al[1] not in seen_ext:
                                                    seen_ext.append('.'+al[1])

                                    p_f = float(len(seen_files)) / float(number_files) * 100
                                    percentage_file_accessed = round(p_f, 2)

                                    if change is True:
                                        if percentage_file_accessed == ticks_exp[tier][current_tick]:
                                            if current_tick not in features.keys():
                                                features[current_tick] = []

                                            f_coverage = calculate_file_type_coverage(nr_files_accessed, seen_ext, extension_counts)
                                            a = float(num_folder_listings) / float(number_folders)
                                            b = float(num_files_read) / float(number_files)
                                            c = float(num_files_written) / float(number_files)
                                            d = float(num_files_renamedmoved) / float(number_files)
                                            if num_files_written == 0:
                                                e = 0
                                            else:
                                                e = write_entropy / float(num_files_written)
                                            feature_vector = [a, b, c, d, f_coverage, e]
                                            features[current_tick].append(feature_vector)
                                            num_folder_listings = 0
                                            num_files_read = 0
                                            num_files_written = 0
                                            num_files_renamedmoved = 0
                                            write_entropy = 0
                                            nr_files_accessed = 0

                                            seen_ext = []
                                            current_tick = current_tick + 1
                                        else:
                                            continue
                                    else:
                                        continue
                            except UnicodeDecodeError:
                               pass
            except Exception as e:
                 pass

        for key, val in features.items():
            with open('datasets/benign_system_centric/' + machine_name + '/tier'+str(tier)+'/' + machine_name + '_' + str(key) + '.csv', 'a+') as fp:
                wr = csv.writer(fp)
                wr.writerows(val)
        print('Finished Benign Folder Session', session_folder_name)
