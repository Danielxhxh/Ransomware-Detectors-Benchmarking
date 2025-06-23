"""
    Train all the Shield-FS classifiers based on Random Forests
"""
import numpy as np
from utilities import load_benign_dataset, load_ransomware_dataset
from sklearn.ensemble import RandomForestClassifier
from joblib import dump
from sklearn import metrics
import sys


benign_path = '/home/dorjan/Projects/ransomware_detector/benign_datasets/benign_process_centric'
ransomware_path = '/home/dorjan/Projects/ransomware_detector/ransomware_datasets/ransomware_process_centric'
# tier = int(sys.argv[3])




# print("Training Models for tier -> ", tier)
all_acc = []
for tier in range(1,28):
    try:
        train_clean_x, train_clean_y, test_clean_x, test_clean_y = load_benign_dataset(tier, benign_path,
                                                                                       test_machine='fa7cfb5aee6be66eac8f135052419cc9')
        train_ransomware_x, train_ransomware_y, test_ransomware_x, test_ransomware_y = load_ransomware_dataset(tier,
                                                                                                               ransomware_path,
                                                                                                               test_folder='part1')
        for k, v in train_clean_x.items():
        #     print(type(k), k)
            clf = RandomForestClassifier(n_estimators=100, verbose=1, max_depth=1000, n_jobs=10)

            train_x = np.concatenate((np.asarray(train_clean_x[k]), np.asarray(train_ransomware_x[k])))
            train_y = np.concatenate((np.asarray(train_clean_y[k]), np.asarray(train_ransomware_y[k])))
            clf.fit(train_x, train_y)

            # dump(clf, 'models/fold1/tier'+str(tier)+'/model_'+str(k)+'.joblib')

            test_y = np.concatenate((np.asarray(test_clean_x[k]), np.asarray(test_ransomware_x[k])))
            y_pred = clf.predict(test_y)
            all_acc.append(metrics.accuracy_score(np.concatenate((np.asarray(test_clean_y[k]), np.asarray(test_ransomware_y[k]))), y_pred))
    except:
        continue

print('Average accureacy', sum(all_acc)/len(all_acc))