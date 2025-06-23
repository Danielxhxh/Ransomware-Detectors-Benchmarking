from joblib import load
from models.random_forest import RandomForestModel

model = RandomForestModel()
model.load('results/rwguard_rf.joblib')

# Predict new data
X_new = [[480,0,349,329,456,0,0,0]]  # Example feature vector
prediction = model.predict(X_new)
print(f"Predicted label: {prediction[0]}")