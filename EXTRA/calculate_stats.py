'''

This file calculates the necessary information needed to compute the feature vectors that will be used to train
a ML model similar to ShieldFS

It counts the number of Folders, files and the extension counts for each machine

'''

import subprocess
import os
import json


# get total number of files in the system
def get_nr_files(machine):

    p = subprocess.Popen(['wc', '-l', machine], stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE)
    result, err = p.communicate()
    if p.returncode != 0:
        raise IOError(err)
    return int(result.strip().split()[0])


# get machine statistics to use for computing the features
def get_machine_statistics(machine):
    number_of_files = 0
    folder_nr = 0
    extension_counts = dict()  # dictionary of this type {'extension': file_count}
    folders = list()

    with open(machine, 'rb') as f:
        for line in f:
            try:
                line = line.decode('utf-8')

                line = line.split(";")
                if 'Windows' not in line[0] and 'Program Files' not in line[0]:
                    number_of_files = number_of_files + 1
                    if line[0] not in folders:
                        folders.append(line[0])
                        folder_nr = folder_nr + 1
                    if line[1] not in extension_counts:
                        extension_counts[line[1]] = 1
                    else:
                        extension_counts[line[1]] = extension_counts[line[1]] + 1
                else:
                    continue
            except UnicodeDecodeError:
                print("The line that had Unicode error: ", line)
                pass
    return folder_nr, number_of_files, extension_counts


machine_statistics_folder = 'models/'


with open('statistics_summary_virtual.txt', 'w') as st:
    st.write("Machine name\tNumber of Folders\tNumber of Files\tExtension Counts\n")

    for filename in os.listdir(machine_statistics_folder):
            folder_nr, number_of_files, extension_counts = get_machine_statistics(machine_statistics_folder+filename)
            print(folder_nr, number_of_files, extension_counts)
            st.write(filename.strip('.csv')+"\t"+str(folder_nr)+"\t"+str(number_of_files)+"\t"+json.dumps(extension_counts, ensure_ascii=False)+"\n")
            print("Finished machine: " + filename.strip('.csv'))
