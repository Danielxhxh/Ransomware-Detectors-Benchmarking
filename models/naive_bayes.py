from sklearn.naive_bayes import GaussianNB
from joblib import dump, load

class NaiveBayesModel:
    def __init__(self, **kwargs):
        """
        Initialize a GaussianNB model with optional hyperparameters from the config.
        kwargs can include 'var_smoothing'.
        """
        self.model = GaussianNB(**kwargs)
        
    def train(self, X, y):
        self.model.fit(X, y)

    def predict(self, X):
        return self.model.predict(X)

    def save(self, path):
        dump(self.model, path)

    def load(self, path):
        self.model = load(path)
