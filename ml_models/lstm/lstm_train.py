import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout
from sklearn.model_selection import train_test_split
from utils import load_dataset

# Load data from .npy files
X, y = load_dataset()

# Reshape for LSTM (samples, timesteps, features)
X = X.reshape(X.shape[0], X.shape[1], 1)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print(f"Training on {X_train.shape[0]} samples, testing on {X_test.shape[0]} samples")

# Model
model = Sequential([
    LSTM(64, input_shape=(X.shape[1], 1), return_sequences=False),
    Dropout(0.2),
    Dense(32, activation='relu'),
    Dropout(0.2),
    Dense(1, activation='sigmoid')
])

model.compile(
    optimizer='adam',
    loss='binary_crossentropy',
    metrics=['accuracy']
)

# Train
print("Training LSTM model...")
model.fit(X_train, y_train, epochs=10, batch_size=32, validation_split=0.1)

# Evaluate
loss, accuracy = model.evaluate(X_test, y_test)
print(f"Test Accuracy: {accuracy:.4f}")

# Save model
model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lstm_model.h5")
model.save(model_path)

print(f"LSTM training complete. Model saved to {model_path}")
