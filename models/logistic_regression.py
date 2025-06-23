from sklearn.linear_model import LogisticRegression
from joblib import dump, load

class LogisticRegressionModel:
    def __init__(self, max_iter=1000, C=1.0, solver='lbfgs', n_jobs=-1):
        self.model = LogisticRegression(
            max_iter=max_iter,
            C=C,
            solver=solver,
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
