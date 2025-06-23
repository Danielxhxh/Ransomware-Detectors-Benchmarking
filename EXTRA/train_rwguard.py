"""
    Train the better Rwguard based on Random Forests
"""
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from joblib import dump
from sklearn import metrics
import csv


benign_train_path = '/home/dhitaj/rw_det/datasets/benign_rwguard/benign_rwguard_features_training_3sec.csv'
ransomware_train_path = '/home/dhitaj/rw_det/datasets/ransomware_rwguard/ransomware_rwguard_features_3sec.csv'

benign_test_path = '/home/dhitaj/rw_det/datasets/benign_rwguard/benign_rwguard_features_test_3sec.csv'
ransomware_test_path = '/home/dhitaj/rw_det/datasets/ransomware_rwguard/ransomware_rwguard_features_test_3sec.csv'

benign_train_x = []
benign_train_y = []

ransomware_train_x = []
ransomware_train_y = []

benign_test_x = []
benign_test_y = []

ransomware_test_x = []
ransomware_test_y = []

with open(benign_train_path) as csv_file:
    csv_reader = list(csv.reader(csv_file, delimiter=','))
    for line in csv_reader:
        benign_train_x.append(line[0:4])
        benign_train_y.append(line[5])


with open(ransomware_train_path) as csv_file:
    csv_reader = list(csv.reader(csv_file, delimiter=','))
    for line in csv_reader:
        ransomware_train_x.append(line[0:4])
        ransomware_train_y.append(line[5])


clf = RandomForestClassifier(n_estimators=100, verbose=1, max_depth=100, n_jobs=14)

train_x = np.concatenate((np.asarray(benign_train_x), np.asarray(ransomware_train_x)))
train_y = np.concatenate((np.asarray(benign_train_y), np.asarray(ransomware_train_y)))
clf.fit(train_x, train_y)

dump(clf, 'rwguard_model.joblib')

with open(benign_test_path) as csv_file:
    csv_reader = list(csv.reader(csv_file, delimiter=','))
    for line in csv_reader:
        benign_test_x.append(line[0:4])
        benign_test_y.append(line[5])


with open(ransomware_test_path) as csv_file:
    csv_reader = list(csv.reader(csv_file, delimiter=','))
    for line in csv_reader:
        ransomware_test_x.append(line[0:4])
        ransomware_test_y.append(line[5])


test_y = np.concatenate((np.asarray(benign_test_x), np.asarray(ransomware_test_x)))
y_pred = clf.predict(test_y)
print("Accuracy:", metrics.accuracy_score(np.concatenate((np.asarray(benign_test_y), np.asarray(ransomware_test_y))),
                                          y_pred))


