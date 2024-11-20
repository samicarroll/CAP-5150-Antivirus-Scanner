import os
import logging
import pickle
import pandas as pd
import fitz  # PyMuPDF
from feature_list import FEATURE_COLUMNS

# Configure logging
logging.basicConfig(level=logging.INFO)

# Load the trained model and feature columns
def load_model_and_features():
    try:
        with open('malicious_classifier.pkl', 'rb') as model_file:
            model = pickle.load(model_file)
        
        feature_columns = FEATURE_COLUMNS

        logging.info(f"Features expected by the model: {model.feature_names_in_ if hasattr(model, 'feature_names_in_') else 'Feature names unavailable in model.'}")
        
        logging.info("Model and feature columns loaded successfully.")

        return model, feature_columns
    except Exception as e:
        logging.error(f"Error loading model or feature columns: {e}")
        raise

# Handle missing features by filling them with dummy values
def handle_missing_features(extracted_features, feature_columns):
    for feature in feature_columns:
        if feature not in extracted_features:
            logging.warning(f"Missing feature: {feature}. Adding dummy value (0).")
            extracted_features[feature] = 0
    return extracted_features

# Process PDF files and make predictions
def process_pdfs(pdf_folder, model, feature_columns):
    files = os.listdir(pdf_folder)
    if not files:
        logging.warning(f"No PDF files found in {pdf_folder}")
        return
    
    for filename in files:
        if filename.endswith('.pdf'):
            pdf_path = os.path.join(pdf_folder, filename)
            logging.info(f"Processing file: {filename}")

            # Extract features from the PDF
            features = extract_pdf_features(pdf_path)

            # Handle missing features
            features = handle_missing_features(features, feature_columns)

            # Align extracted features with model's expected input
            feature_array = pd.DataFrame([features], columns=feature_columns)

            try:
                # Make prediction
                prediction = model.predict(feature_array.values)
                logging.info(f"Prediction for {filename}: {prediction[0]}")
            except Exception as e:
                logging.error(f"Error making prediction for {filename}: {e}")

def extract_pdf_features(pdf_path):
    """
    Extract features from a PDF file for prediction.
    """
    features = {key: 0 for key in FEATURE_COLUMNS}  # Initialize with all features
    
    try:
        # General PDF properties
        features["pdf_size"] = os.path.getsize(pdf_path)
        doc = fitz.open(pdf_path)
        features["encryption"] = int(doc.is_encrypted)
        features["page_number"] = doc.page_count
        features["title_characters"] = len(doc.metadata.get("title", "")) if doc.metadata else 0
        features["metadata_size"] = len(str(doc.metadata)) if doc.metadata else 0

        # Extract text and object details
        text_length, image_count, font_count = 0, 0, 0
        for page in doc:
            text = page.get_text("text")
            text_length += len(text)
            image_count += len(page.get_images(full=True))
            font_count += len(page.get_fonts(full=True))

        features["text"] = text_length
        features["image_number"] = image_count
        features["font_objects"] = font_count

        # Embedded files
        embedded_files = extract_embedded_files(doc)
        features["embedded_files"] = len(embedded_files)
        if embedded_files:
            features["avg_embedded_media_size"] = sum(embedded_files) / len(embedded_files)

        # Structural analysis
        raw_content = open(pdf_path, "rb").read()
        raw_content_str = raw_content.decode(errors="ignore")
        features["stream_count"] = raw_content_str.count("stream")
        features["endstream_count"] = raw_content_str.count("endstream")
        streams = [len(s) for s in raw_content_str.split("stream")[1:]]
        features["avg_stream_size"] = sum(streams) / len(streams) if streams else 0
        features["xref_entries"] = raw_content_str.count("xref")
        features["name_obfuscations"] = raw_content_str.count("/Name")
        features["total_filters"] = raw_content_str.count("/Filter")
        features["nested_filters"] = raw_content_str.count("/FlateDecode")
        features["stream_objects"] = raw_content_str.count("stream")

        # Count keywords
        keywords = [
            "/JS", "/JavaScript", "/URI", "/Action", "/AA", "/OpenAction", "/launch",
            "/submitForm", "/Acroform", "/XFA", "/JBig2Decode", "/Colors", "/Richmedia",
            "/Trailer", "/Xref", "/Startxref"
        ]
        for keyword in keywords:
            features[f"{keyword}_keywords"] = raw_content_str.count(keyword)

    except Exception as e:
        logging.error(f"Error extracting features from {pdf_path}: {e}")

    return features

def extract_embedded_files(doc):
    """
    Extract sizes of embedded files in a PDF.
    """
    embedded_files = []
    try:
        if hasattr(doc, 'embedded_file_count'):
            for i in range(doc.embedded_file_count):
                embedded_file = doc.embedded_file(i)
                embedded_files.append(len(embedded_file["content"]))
    except Exception as e:
        logging.error(f"Error extracting embedded files: {e}")
    return embedded_files


def main():
    model, feature_columns = load_model_and_features()
    pdf_folder = input("Enter directory to scan for malicious files: ")
    process_pdfs(pdf_folder, model, feature_columns)

if __name__ == "__main__":
    main()
