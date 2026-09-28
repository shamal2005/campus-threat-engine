import os
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import joblib

# Step 1: Load the dataset from ml/data/
base_dir = os.path.dirname(os.path.abspath(__file__))
data_path = os.path.join(base_dir, "data", "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")
print(f"Loading data from: {data_path}...")
df = pd.read_csv(data_path)

# Step 2: Strip whitespace from column names
df.columns = df.columns.str.strip()

# Step 3: Replace infinite values with NaN and drop rows with missing/bad values
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# Step 4: Make the label binary: BENIGN = 0, PortScan = 1
df["Label"] = df["Label"].str.strip()
df["Label"] = df["Label"].apply(lambda x: 0 if x == "BENIGN" else 1)

# Separate input features (X) and target label (y)
X = df.drop(columns=["Label"])
y = df["Label"]
feature_columns = list(X.columns)

# Step 5: Split data into 80% training and 20% testing sets (stratified)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)
print(f"Dataset split: {len(X_train)} train samples, {len(X_test)} test samples.")

# Step 6: Train a RandomForestClassifier
print("Training RandomForestClassifier...")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# Step 7: Print evaluation metrics and confusion matrix
y_pred = model.predict(X_test)
print("\n--- Evaluation Metrics ---")
print(f"Accuracy:  {accuracy_score(y_test, y_pred):.4f}")
print(f"Precision: {precision_score(y_test, y_pred):.4f}")
print(f"Recall:    {recall_score(y_test, y_pred):.4f}")
print(f"F1 Score:  {f1_score(y_test, y_pred):.4f}")
print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Step 8: Save the trained model and feature list with joblib
model_path = os.path.join(base_dir, "model.joblib")
features_path = os.path.join(base_dir, "features.joblib")

joblib.dump(model, model_path)
joblib.dump(feature_columns, features_path)
print(f"\nModel saved to: {model_path}")
print(f"Features saved to: {features_path}")
