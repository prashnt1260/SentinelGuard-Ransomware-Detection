import os
import io
import tempfile
import json
import logging
import numpy as np
import pandas as pd
import pefile
from flask import Flask, render_template, request, jsonify
# Using joblib for loading both model and pickled feature columns
import joblib 

# --- Configuration and Setup ---
# Set up logging
logging.basicConfig(level=logging.INFO)

# Define file paths using the paths from your successful training script
MODEL_PATH = 'models/ransomware_detector.pkl'
FEATURES_PATH = 'models/feature_columns.pkl' # This is now a .pkl file

# Initialize Flask App
app = Flask(__name__)

# Global variables for the model and features
model = None
feature_columns = []

# --- Helper Functions ---

def load_model_and_features():
    """Loads the trained model and feature list."""
    global model, feature_columns
    try:
        # Load the trained model (.pkl)
        model = joblib.load(MODEL_PATH)
        logging.info(f"Model loaded successfully from {MODEL_PATH}")
    except FileNotFoundError:
        logging.error(f"Model file not found at {MODEL_PATH}. Check if the 'models' folder exists and training was completed.")
        return False
    except Exception as e:
        logging.error(f"Error loading model: {e}")
        return False

    try:
        # Load the feature list (.pkl) using joblib
        feature_columns = joblib.load(FEATURES_PATH)
        if not isinstance(feature_columns, list):
            # Handle case where pickle content is unexpected format
            logging.warning("Feature columns loaded but is not a list. Assuming training failed.")
            feature_columns = ['SizeOfOptionalHeader', 'SizeOfCode', 'SizeOfInitializedData', 'CheckSum', 'NumberOfSections']

        logging.info(f"Feature list loaded successfully. Total features: {len(feature_columns)}")
        return True
    except FileNotFoundError:
        logging.error(f"Feature list file not found at {FEATURES_PATH}. Check if training was completed.")
        return False
    except Exception as e:
        logging.error(f"Error loading features: {e}")
        return False


def extract_features(pe_data):
    """
    Extracts a large set of PE features from the byte data of an executable.
    
    This function extracts all features the model *might* need. The final
    DataFrame is then filtered using the 'feature_columns' list loaded from the PKL.
    """
    features = {}
    try:
        # Load the PE file from memory
        pe = pefile.PE(data=pe_data)

        # --- PE Header Features ---
        features['Magic'] = pe.OPTIONAL_HEADER.Magic
        features['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
        features['Machine'] = pe.FILE_HEADER.Machine
        features['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
        features['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
        features['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
        features['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        features['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
        features['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
        features['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
        features['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
        features['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        features['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
        features['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
        features['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
        features['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
        features['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
        features['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
        features['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
        features['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
        features['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
        features['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
        features['NumberOfSections'] = pe.FILE_HEADER.NumberOfSections
        features['TimeDateStamp'] = pe.FILE_HEADER.TimeDateStamp

        # --- Section Features (Example: Entropy) ---
        section_entropies = [s.get_entropy() for s in pe.sections]
        features['EntropyMin'] = min(section_entropies) if section_entropies else 0
        features['EntropyMax'] = max(section_entropies) if section_entropies else 0
        features['EntropyMean'] = np.mean(section_entropies) if section_entropies else 0

        # --- Import/Export Features ---
        features['NumberOfImports'] = len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0
        features['NumberOfExports'] = pe.DIRECTORY_ENTRY_EXPORT.NumberOfFunctions if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0

        # Close the PE file
        pe.close()

    except pefile.PEFormatError:
        logging.warning("PEFormatError: File is not a valid PE executable.")
        # Return zeros for all required features if file is invalid
        return {f: 0 for f in feature_columns}
    except Exception as e:
        logging.error(f"Error during feature extraction: {e}")
        # Return zeros for all required features if error occurs
        return {f: 0 for f in feature_columns}

    return features


def get_top_features(features_df, probability):
    """
    Determines and reports the most influential features based on the model's
    feature importances (RandomForest) or coefficients (LogisticRegression).
    """
    
    # 1. Get model importance scores
    if hasattr(model, 'feature_importances_'):
        # For RandomForest or other tree-based models
        importances = model.feature_importances_
        feature_importance_map = dict(zip(feature_columns, importances))
    elif hasattr(model, 'coef_') and model.coef_.shape[1] == len(feature_columns):
        # Fallback for Logistic Regression or linear models
        importances = np.abs(model.coef_[0])
        feature_importance_map = dict(zip(feature_columns, importances))
    else:
        # Fallback: Equal importance
        feature_importance_map = {f: 1.0 for f in feature_columns}

    # 2. Heuristics for "suspicious" features (simplified for UI)
    suspicious_keywords = ['Section', 'Entropy', 'Import', 'SizeOfUninitializedData', 'SizeOfStackReserve', 'SizeOfHeapReserve', 'TimeDateStamp']
    
    # 3. Compile list of features with calculated scores
    feature_scores = []
    
    for feature_name, importance_score in feature_importance_map.items():
        # Ensure the feature name exists in the input DataFrame
        feature_value = features_df[feature_name].iloc[0] if feature_name in features_df.columns else 0
        
        # Calculate a combined score: importance * probability 
        # (This is a simplified way to weight importance by prediction confidence)
        score = importance_score * probability * (1 if probability > 0.5 else 0.5) 
        
        # Determine feature type for UI coloring
        f_type = 'structural'
        
        # Mark as suspicious if it's a known high-risk feature or has high importance
        if any(keyword in feature_name for keyword in suspicious_keywords) and feature_value > 0:
             f_type = 'suspicious'
        elif importance_score > 0.05 and probability > 0.5: # 5% importance threshold
             f_type = 'suspicious'

        feature_scores.append({
            'name': feature_name,
            'score': float(f'{score:.4f}'), # Round the score for clean display
            'type': f_type # Used by the front-end for coloring (red/green)
        })

    # 4. Sort and return top 10 contributing features
    feature_scores.sort(key=lambda x: x['score'], reverse=True)
    
    return feature_scores[:10]


# --- Flask Routes ---

@app.route('/')
def index():
    """Renders the main analysis interface."""
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    """Handles the file upload, feature extraction, and model prediction."""
    if not model or not feature_columns:
        return jsonify({"error": "Model not loaded. Check server logs."}), 503
        
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if file:
        logging.info(f"Received file: {file.filename}")

        # Read file data directly into memory to pass to pefile
        pe_data = file.read()
        
        # 1. Extract raw features (extracts all available features)
        raw_features = extract_features(pe_data)
        
        # 2. Create a standardized DataFrame for the model
        # Filter the raw features dictionary to only include features the model was trained on
        features_dict = {f: raw_features.get(f, 0) for f in feature_columns}
        features_df = pd.DataFrame([features_dict], columns=feature_columns)
        
        # Check if the dataframe is empty or malformed
        if features_df.empty or features_df.shape[1] != len(feature_columns):
             return jsonify({"error": "Feature extraction failed or returned incorrect format."}), 500

        # 3. Model Prediction
        try:
            # Predict class (0 or 1)
            prediction_class = model.predict(features_df)[0]
            # Predict probability of being class 1 (Ransomware)
            probability_ransomware = model.predict_proba(features_df)[0][1]
        except Exception as e:
            logging.error(f"Model prediction failed: {e}")
            return jsonify({"error": f"Model prediction failed: {e}"}), 500

        # 4. Determine prediction text
        is_ransomware = int(prediction_class) == 1
        prediction_text = "Ransomware Detected" if is_ransomware else "Safe"
        
        # 5. Get top features for the UI
        top_features = get_top_features(features_df, probability_ransomware)

        # 6. Return results
        return jsonify({
            "filename": file.filename,
            "prediction": prediction_text,
            "is_ransomware": int(is_ransomware),
            "probability_ransomware": float(probability_ransomware),
            "top_features": top_features
        })

    return jsonify({"error": "Unknown error during file processing"}), 500

# Load model and features on application startup
with app.app_context():
    if not load_model_and_features():
        logging.critical("CRITICAL: Failed to load model or features. Application will not function correctly.")

if __name__ == '__main__':
    # Note: Removed the dummy check since the user successfully ran train_model.py
    app.run(debug=True, port=5000)
