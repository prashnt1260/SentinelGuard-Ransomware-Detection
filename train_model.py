import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import pickle
import os
from utils.data_processor import create_training_dataframe

# --- Configuration ---
BENIGN_SAMPLES_DIR = 'data/raw_samples/benign/'
RANSOMWARE_SAMPLES_DIR = 'data/raw_samples/ransomware/'
PROCESSED_DATA_CSV = 'data/processed_features.csv'
MODEL_PATH = 'models/ransomware_detector.pkl'
FEATURE_COLUMNS_PATH = 'models/feature_columns.pkl'

def train_and_save_model():
    # Ensure directories exist
    os.makedirs(os.path.dirname(PROCESSED_DATA_CSV), exist_ok=True)
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    os.makedirs(BENIGN_SAMPLES_DIR, exist_ok=True)
    os.makedirs(RANSOMWARE_SAMPLES_DIR, exist_ok=True)

    # --- 1. Create/Load Dataset ---
    print("--- STEP 1: Preparing Dataset ---")
    df = create_training_dataframe(BENIGN_SAMPLES_DIR, RANSOMWARE_SAMPLES_DIR, PROCESSED_DATA_CSV, FEATURE_COLUMNS_PATH)
    
    if df is None or df.empty:
        print("Exiting: No data available for training. Ensure you have samples in data/raw_samples/benign/ and data/raw_samples/ransomware/.")
        return

    X = df.drop('label', axis=1)
    y = df['label']

    print(f"\nDataset loaded with {len(X)} samples and {len(X.columns)} features.")
    print(f"Class distribution: Benign ({len(y[y==0])}), Ransomware ({len(y[y==1])})")

    # --- 2. Split Data ---
    print("\n--- STEP 2: Splitting Data (80% Train, 20% Test) ---")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.5, random_state=42, stratify=y)
    print(f"Training samples: {len(X_train)}, Testing samples: {len(X_test)}")

    # --- 3. Train Model ---
    print("\n--- STEP 3: Training RandomForest Classifier ---")
    # Using RandomForestClassifier, 'balanced' class_weight helps with imbalanced datasets
    model = RandomForestClassifier(n_estimators=150, random_state=42, class_weight='balanced', n_jobs=-1)
    model.fit(X_train, y_train)
    print("Model training complete.")

    # --- 4. Evaluate Model ---
    print("\n--- STEP 4: Evaluating Model Performance ---")
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1] # Probability of ransomware

    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Ransomware']))
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    # --- 5. Save Model and Feature Columns ---
    print("\n--- STEP 5: Saving Model and Feature Columns ---")
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    print(f"Trained model saved to {MODEL_PATH}")

    # The feature columns are already saved by create_training_dataframe
    # but we'll confirm its presence here or if you had specific post-processing, save again.
    # For now, it's handled by data_processor.py
    if not os.path.exists(FEATURE_COLUMNS_PATH):
        print(f"Warning: {FEATURE_COLUMNS_PATH} was not found. Please ensure data_processor saved it.")


if __name__ == '__main__':
    # Important: Before running this script:
    # 1. Manually create data/raw_samples/benign/ and data/raw_samples/ransomware/
    # 2. Populate these directories with actual benign and ransomware executable files.
    #    *** USE VIRTUAL MACHINES OR SANDBOXES FOR RANSOMWARE SAMPLES ***
    #    (e.g., place clean EXEs in 'benign' and test ransomware samples in 'ransomware')
    print("Starting SentinelGuard Model Training...")
    train_and_save_model()
    print("Training process finished.")