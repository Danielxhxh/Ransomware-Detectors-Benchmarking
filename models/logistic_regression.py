from sklearn.linear_model import LogisticRegression
from joblib import dump, load

class LogisticRegressionModel:
    def __init__(self, **kwargs):
        """
        Initialize a LogisticRegression model with hyperparameters from the config.
        kwargs can include: max_iter, C, solver, n_jobs, penalty, etc.
        """
        self.model = LogisticRegression(**kwargs)
        print("LogisticRegressionModel initialized with parameters:")
        print(self.model.get_params())
    def train(self, X, y):
        self.model.fit(X, y)

    def predict(self, X):
        return self.model.predict(X)

    def save(self, path):
        dump(self.model, path)

    def load(self, path):
        self.model = load(path)
