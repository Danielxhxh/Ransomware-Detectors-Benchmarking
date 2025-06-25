from ml_models.random_forest import RandomForestModel
from ml_models.logistic_regression import LogisticRegressionModel
from ml_models.naive_bayes import NaiveBayesModel

MODEL_REGISTRY = {
    'random_forest': RandomForestModel,
    'logistic_regression': RandomForestModel,  
    'naive_bayes': NaiveBayesModel
    
}
