import pandas as pd
import numpy as np

LABEL_COLUMN = "Malware"   # CHANGE ONLY IF NEEDED

df = pd.read_csv("data/static_dataset.csv")

X = df.drop(columns=[LABEL_COLUMN])
y = df[LABEL_COLUMN]

X = X.values.astype(np.float32)
y = y.values.astype(np.int64)

print("X shape:", X.shape)
print("y shape:", y.shape)
print("Malware ratio:", y.mean())

np.save("X.npy", X)
np.save("y.npy", y)
