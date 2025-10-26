# train_model.py

import os
import pickle
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# --- Config ---
BASE = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE, "data", "dataset_raw.csv")   # your original CSV
MODEL_DIR = os.path.join(BASE, "model")
MODEL_PATH = os.path.join(MODEL_DIR, "random_forest_model.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")
FEATURES_PATH = os.path.join(MODEL_DIR, "feature_names.pkl")

os.makedirs(MODEL_DIR, exist_ok=True)

# --- Load dataset ---
if not os.path.exists(DATA_PATH):
    raise FileNotFoundError(f"Dataset not found at {DATA_PATH}. Please put dataset_raw.csv there.")

print("Loading dataset:", DATA_PATH)
df = pd.read_csv(DATA_PATH)
print("Records:", len(df), "Columns:", list(df.columns))

# --- Basic cleanup: ensure label column exists ---
if 'label' not in df.columns:
    raise ValueError("CSV must contain a 'label' column with 0 (clean) and 1 (malicious).")

# --- Drop any columns not used (file_id, path, notes) if present ---
drop_cols = [c for c in ['file_id','file_path','notes'] if c in df.columns]
if drop_cols:
    print("Dropping columns:", drop_cols)
    df = df.drop(columns=drop_cols)

# --- Handle categorical ext column if present ---
if 'ext' in df.columns:
    # Keep original ext categories ordering for app encoding
    df['ext'] = df['ext'].astype('category')
    ext_categories = list(df['ext'].cat.categories)
    # encode
    df['ext'] = df['ext'].cat.codes
else:
    ext_categories = None

# --- Fill missing values with sensible defaults ---
df = df.fillna(0)

# --- Features & labels ---
X = df.drop(columns=['label'])
y = df['label']

# --- Train/test split (stratify to keep class ratio) ---
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("Train samples:", len(X_train), "Test samples:", len(X_test))
print("Feature columns:", list(X.columns))

# --- Scale features ---
scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s = scaler.transform(X_test)

# --- Train Random Forest (GridSearch optional, but default tuned params used) ---
print("Training Random Forest...")
rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    min_samples_split=4,
    min_samples_leaf=2,
    max_features='sqrt',
    random_state=42,
    class_weight='balanced_subsample'
)
rf.fit(X_train_s, y_train)

# --- Evaluate ---
y_pred = rf.predict(X_test_s)
y_proba = rf.predict_proba(X_test_s)[:, 1]

acc = accuracy_score(y_test, y_pred)
print(f"\nAccuracy: {acc*100:.2f}%")
print("\nClassification Report:")
print(classification_report(y_test, y_pred))
print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# --- Feature importances ---
try:
    importances = pd.Series(rf.feature_importances_, index=X.columns).sort_values(ascending=False)
    print("\nTop feature importances:")
    print(importances.head(10))
except Exception:
    pass

# --- Save artifacts ---
with open(MODEL_PATH, "wb") as f:
    pickle.dump(rf, f)
with open(SCALER_PATH, "wb") as f:
    pickle.dump(scaler, f)
# Save feature names and ext categories for consistent encoding in app.py
meta = {
    "feature_names": list(X.columns),
    "ext_categories": ext_categories  # may be None
}
with open(FEATURES_PATH, "wb") as f:
    pickle.dump(meta, f)

print("\nSaved model and scaler to:", MODEL_DIR)
print("Done.")
