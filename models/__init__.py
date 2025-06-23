from models.random_forest import RandomForestModel
from models.logistic_regression import LogisticRegressionModel
# from models.xgboost import XGBoostModel
# from models.svm import SVMModel
# etc.

MODEL_REGISTRY = {
    'random_forest': RandomForestModel,
    'logistic_regression': RandomForestModel,  
    # 'xgboost': XGBoostModel,
    # 'svm': SVMModel,
}
