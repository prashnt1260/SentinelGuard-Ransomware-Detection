import pickle
import os
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import numpy as np

# --- Configuration ---
MODEL_PATH = 'models/ransomware_detector.pkl'
FEATURE_COLUMNS_PATH = 'models/feature_columns.pkl'
MODEL_DIR = 'models'

def generate_and_save_dummy_model():
    """
    Creates a simple dummy RandomForest model and saves it along with the 
    expected feature column list. This allows the API to start without 
    a real trained model.
    """
    os.makedirs(MODEL_DIR, exist_ok=True)
    
    # Define the exact features expected by the data processor and app.py
    feature_columns = [
        'pe_data_file_size', 'pe_data_entropy', 'pe_data_num_sections', 'pe_data_entry_point',
        'pe_data_major_linker_version', 'pe_data_minor_linker_version', 'pe_data_image_base',
        'pe_data_number_of_rva_and_sizes', 'pe_data_characteristics_dll',
        'pe_data_characteristics_executable_image', 'pe_data_characteristics_32bit_machine',
        'pe_data_timestamp', 'pe_data_has_debug_info', 'pe_data_num_imported_dlls',
        'pe_data_num_imported_functions', 'pe_data_has_resource_section', 'pe_data_has_reloc_section',
        'pe_data_is_packed_upx', 'pe_data_VirtualAlloc_import', 'pe_data_CreateRemoteThread_import',
        'pe_data_WriteProcessMemory_import', 'pe_data_NtCreateSection_import', 'pe_data_RegSetValueEx_import',
        'pe_data_CryptEncrypt_import', 'pe_data_SetWindowsHookEx_import', 'pe_data_LoadLibrary_import',
        'pe_data_GetProcAddress_import'
    ]
    
    print(f"Creating dummy model based on {len(feature_columns)} features...")

    # Create dummy data (10 samples for a quick training)
    X = np.random.rand(10, len(feature_columns))
    y = np.array([0, 1, 0, 1, 0, 1, 0, 1, 0, 1])
    
    # Train a minimal classifier
    model = RandomForestClassifier(n_estimators=10, random_state=42)
    model.fit(X, y)

    # Manually set feature importances to show meaningful results in the UI
    importances = np.zeros(len(feature_columns))
    importances[feature_columns.index('pe_data_entropy')] = 0.2
    importances[feature_columns.index('pe_data_VirtualAlloc_import')] = 0.15
    importances[feature_columns.index('pe_data_CreateRemoteThread_import')] = 0.1
    importances[feature_columns.index('pe_data_is_packed_upx')] = 0.08
    importances[feature_columns.index('pe_data_file_size')] = 0.05
    
    model.feature_importances_ = importances / np.sum(importances)
    
    
    # 1. Save feature columns
    with open(FEATURE_COLUMNS_PATH, 'wb') as f:
        pickle.dump(feature_columns, f)
    print(f"Dummy feature columns saved to {FEATURE_COLUMNS_PATH}")

    # 2. Save dummy model
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    print(f"Dummy model saved to {MODEL_PATH}")

if __name__ == '__main__':
    generate_and_save_dummy_model()
    print("Dummy model generation complete. You can now run 'python app.py'.")
