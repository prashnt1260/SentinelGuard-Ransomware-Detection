import pandas as pd
import os
import pickle
from .pe_analyzer import extract_pe_features # Relative import

def process_files_for_features(directory, label):
    """
    Processes all PE files in a given directory, extracts features,
    and returns a list of dictionaries with features and a label.
    """
    all_features = []
    print(f"Processing directory: {directory} with label: {label}")
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        if os.path.isfile(filepath):
            print(f"  Extracting features from: {filename}")
            features = extract_pe_features(filepath)
            if features:
                features['label'] = label # Add the label
                all_features.append(features)
            else:
                print(f"  Skipping {filename}: Not a valid PE file or error during extraction.")
    return all_features

def create_training_dataframe(benign_dir, ransomware_dir, output_csv, feature_columns_path):
    """
    Extracts features from benign and ransomware samples, combines them into a DataFrame,
    and saves it to a CSV. Also saves the list of feature columns.
    """
    print("Starting data processing for training...")
    benign_features = process_files_for_features(benign_dir, 0) # 0 for benign
    ransomware_features = process_files_for_features(ransomware_dir, 1) # 1 for ransomware

    all_data = benign_features + ransomware_features
    if not all_data:
        print("No features extracted. Ensure your sample directories contain valid PE files.")
        return None

    df = pd.DataFrame(all_data)
    
    # Fill any potential NaNs with 0 (for features that might not be present in all PE files)
    df = df.fillna(0)

    # Reorder columns to ensure 'label' is last, and save the feature column order
    # (excluding 'label' for X)
    cols = [col for col in df.columns if col != 'label'] + ['label']
    df = df[cols]

    # Save the feature columns to a pickle file for consistent use during prediction
    with open(feature_columns_path, 'wb') as f:
        pickle.dump(df.drop('label', axis=1).columns.tolist(), f)
    print(f"Feature columns saved to {feature_columns_path}")

    df.to_csv(output_csv, index=False)
    print(f"Processed dataset saved to {output_csv}")
    return df

def prepare_single_file_features(filepath, expected_feature_columns_path):
    """
    Extracts features from a single file and converts them into a DataFrame
    ready for prediction, ensuring consistent column order and handling missing features.
    """
    features = extract_pe_features(filepath)
    if not features:
        return None

    # Load the expected feature columns from the training phase
    try:
        with open(expected_feature_columns_path, 'rb') as f:
            expected_columns = pickle.load(f)
    except FileNotFoundError:
        print(f"Error: {expected_feature_columns_path} not found. Train your model first.")
        return None

    # Create a DataFrame from the extracted features
    df_single_file = pd.DataFrame([features])

    # Ensure all expected columns are present, fill missing with 0
    for col in expected_columns:
        if col not in df_single_file.columns:
            df_single_file[col] = 0
    
    # Reorder columns to match the training data
    df_single_file = df_single_file[expected_columns]
    
    return df_single_file