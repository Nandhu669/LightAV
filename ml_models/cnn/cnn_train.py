import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv1D, MaxPooling1D, Flatten, Dense
from sklearn.model_selection import train_test_split
from utils import load_dataset

# Load data from .npy files
X, y = load_dataset()

# Reshape for CNN (samples, features, channels)
X = X.reshape(X.shape[0], X.shape[1], 1)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print(f"Training on {X_train.shape[0]} samples, testing on {X_test.shape[0]} samples")

# Model
model = Sequential([
    Conv1D(32, 3, activation='relu', input_shape=(X.shape[1], 1)),
    MaxPooling1D(2),
    Conv1D(64, 3, activation='relu'),
    Flatten(),
    Dense(64, activation='relu'),
    Dense(1, activation='sigmoid')
])

model.compile(
    optimizer='adam',
    loss='binary_crossentropy',
    metrics=['accuracy']
)

# Train
print("Training CNN model...")
model.fit(X_train, y_train, epochs=10, batch_size=32, validation_split=0.1)

# Evaluate
loss, accuracy = model.evaluate(X_test, y_test)
print(f"Test Accuracy: {accuracy:.4f}")

# Save model
model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cnn_model.h5")
model.save(model_path)

print(f"CNN training complete. Model saved to {model_path}")
