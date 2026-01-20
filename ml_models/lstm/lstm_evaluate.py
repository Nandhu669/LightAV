import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tensorflow.keras.models import load_model
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from utils import load_dataset
import numpy as np

# Load data
X, y = load_dataset()
X = X.reshape(X.shape[0], X.shape[1], 1)

# Load model
model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lstm_model.h5")
model = load_model(model_path)

print("Evaluating LSTM model...")
print("=" * 50)

# Predictions
preds = (model.predict(X) > 0.5).astype(int).flatten()

# Metrics
accuracy = accuracy_score(y, preds)
print(f"\nAccuracy: {accuracy:.4f}")

print("\nClassification Report:")
print(classification_report(y, preds, target_names=["Benign", "Malicious"]))

print("\nConfusion Matrix:")
cm = confusion_matrix(y, preds)
print(cm)
print(f"\nTrue Negatives: {cm[0][0]}, False Positives: {cm[0][1]}")
print(f"False Negatives: {cm[1][0]}, True Positives: {cm[1][1]}")
