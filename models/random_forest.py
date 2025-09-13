from sklearn.ensemble import RandomForestClassifier
from joblib import dump, load

class RandomForestModel:
    def __init__(self, **kwargs):
        """
        Initialize a RandomForestClassifier with hyperparameters from the config.
        kwargs can include:
        n_estimators, max_depth, min_samples_split, min_samples_leaf, max_features,
        bootstrap, class_weight, random_state, n_jobs, etc.
        """
        self.model = RandomForestClassifier(**kwargs)

    def train(self, X, y):
        self.model.fit(X, y)

    def predict(self, X):
        return self.model.predict(X)

    def save(self, path):
        dump(self.model, path)

    def load(self, path):
        self.model = load(path)
