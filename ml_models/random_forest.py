from sklearn.ensemble import RandomForestClassifier
from joblib import dump, load

class RandomForestModel:
    def __init__(self, n_estimators=100, max_depth=100, n_jobs=-1):
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            n_jobs=n_jobs
        )

    def train(self, X, y):
        self.model.fit(X, y)

    def predict(self, X):
        return self.model.predict(X)

    def save(self, path):
        dump(self.model, path)

    def load(self, path):
        self.model = load(path)
