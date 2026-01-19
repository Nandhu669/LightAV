import numpy as np
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

# Load balanced dataset
X = np.load("X_balanced.npy")
y = np.load("y_balanced.npy")

# Train / test split
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    stratify=y,
    random_state=42
)

# LightGBM model (safe defaults)
model = lgb.LGBMClassifier(
    n_estimators=300,
    learning_rate=0.05,
    max_depth=8,
    num_leaves=64,
    random_state=42
)

# Train
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)

print(classification_report(y_test, y_pred))

# Save model
joblib.dump(model, "lightgbm_static_balanced.pkl")