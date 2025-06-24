from sklearn.naive_bayes import GaussianNB
from joblib import dump, load

class NaiveBayesModel:
    def __init__(self):
        self.model = GaussianNB()

    def train(self, X, y):
        self.model.fit(X, y)

    def predict(self, X):
        return self.model.predict(X)

    def save(self, path):
        dump(self.model, path)

    def load(self, path):
        self.model = load(path)
