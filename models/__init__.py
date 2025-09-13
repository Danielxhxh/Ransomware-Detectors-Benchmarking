from models.random_forest import RandomForestModel
from models.logistic_regression import LogisticRegressionModel
from models.naive_bayes import NaiveBayesModel

MODEL_REGISTRY = {
    'random_forest': RandomForestModel,
    'logistic_regression': LogisticRegressionModel,  
    'naive_bayes': NaiveBayesModel
    
}
