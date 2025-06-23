import numpy as np
import csv
from joblib import load
from sklearn import metrics
import os
import sys

# ransomware_file_path = '/home/dorjan/Projects/ransomware_detector/rwguard/new_model/evasion/'
ransomware_file_path = '/home/dorjan/Projects/ransomware_detector/rwguard/'

folder = sys.argv[1]

acc_list = []

for file in os.listdir(ransomware_file_path+folder):
    file_path = os.path.join(ransomware_file_path+folder, file)
    ransomware_test_x = []
    ransomware_test_y = []

    with open(file_path) as csv_file:
        csv_reader = list(csv.reader(csv_file, delimiter=','))
        for line in csv_reader:
            ransomware_test_x.append(line[0:8])
            ransomware_test_y.append(line[8])

        ransomware_test_x = np.asarray(ransomware_test_x)
        ransomware_test_y = np.asarray(ransomware_test_y)

        clf = load('/home/dorjan/Projects/ransomware_detector/rwguard/new_model/new_rwguard_model.joblib')
        y_pred = clf.predict(ransomware_test_x)
        acc = metrics.accuracy_score(ransomware_test_y, y_pred)
        print(file, round(acc,6))
        # f_num = int(file.split('.')[0].split('_')[2])

        # acc_list.append([f_num, round(acc, 6)])

# from operator import itemgetter
# outputlist = sorted(acc_list, key=itemgetter(0), reverse=False)
# print(outputlist)
# print(np.matrix(acc_list))
