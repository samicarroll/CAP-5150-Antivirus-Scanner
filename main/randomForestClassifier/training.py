import os
import zipfile
import shutil
import logging
import magic  # For file type identification
from collections import Counter
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from imblearn.over_sampling import SMOTE
from sklearn.impute import SimpleImputer
import matplotlib.pyplot as plt
import pickle
import numpy as np
import fitz  # PyMuPDF
from feature_list import FEATURE_COLUMNS

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# Function to create a temporary folder for extracting ZIP contents
def create_temporary_folder():
    temp_folder = 'temporary'
    if not os.path.exists(temp_folder):
        try:
            os.makedirs(temp_folder)
            print(f"Temporary folder created at: {os.path.abspath(temp_folder)}")
            logging.debug(f"Temporary folder created at: {os.path.abspath(temp_folder)}")
        except Exception as e:
            logging.error(f"Error creating temporary folder: {e}")
            print(f"Error creating temporary folder: {e}")
    else:
        print(f"Temporary folder already exists at: {os.path.abspath(temp_folder)}")
        logging.debug(f"Temporary folder already exists at: {os.path.abspath(temp_folder)}")
    return temp_folder

# Function to clean up the temporary folder after extraction
def cleanup_temporary_folder(temp_folder):
    if os.path.exists(temp_folder):
        try:
            shutil.rmtree(temp_folder)
            print(f"Temporary folder cleaned up: {os.path.abspath(temp_folder)}")
            logging.debug(f"Temporary folder cleaned up: {os.path.abspath(temp_folder)}")
        except Exception as e:
            logging.error(f"Error cleaning up temporary folder: {e}")
            print(f"Error cleaning up temporary folder: {e}")

def extract_pdf_features(pdf_path):
    """
    Extracts general and structural features from a PDF.
    """
    features = {
        "pdf_size": 0,
        "title_characters": 0,
        "encryption": 0,
        "metadata_size": 0,
        "page_number": 0,
        "header": 0,
        "image_number": 0,
        "text": 0,
        "object_number": 0,
        "font_objects": 0,
        "embedded_files": 0,
        "avg_embedded_media_size": 0,
        # Structural features
        "stream_count": 0,
        "endstream_count": 0,
        "avg_stream_size": 0,
        "xref_entries": 0,
        "name_obfuscations": 0,
        "total_filters": 0,
        "nested_filters": 0,
        "stream_objects": 0,
        "/JS_keywords": 0,
        "/JavaScript_keywords": 0,
        "/URI_keywords": 0,
        "/Action_keywords": 0,
        "/AA_keywords": 0,
        "/OpenAction_keywords": 0,
        "/launch_keywords": 0,
        "/submitForm_keywords": 0,
        "/Acroform_keywords": 0,
        "/XFA_keywords": 0,
        "/JBig2Decode_keywords": 0,
        "/Colors_keywords": 0,
        "/Richmedia_keywords": 0,
        "/Trailer_keywords": 0,
        "/Xref_keywords": 0,
        "/Startxref_keywords": 0
    }

    try:
        # General features
        features["pdf_size"] = os.path.getsize(pdf_path)
        doc = fitz.open(pdf_path)
        features["encryption"] = int(doc.is_encrypted)
        features["page_number"] = doc.page_count
        features["title_characters"] = len(doc.metadata.get("title", "")) if doc.metadata else 0
        features["metadata_size"] = len(str(doc.metadata)) if doc.metadata else 0

        # Analyze objects and text
        text_length, image_count, font_count, embedded_files_size = 0, 0, 0, 0
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

        # Structural features
        raw_content = open(pdf_path, "rb").read()
        raw_content_str = raw_content.decode(errors="ignore")

        features["stream_count"] = raw_content_str.count("stream")
        features["endstream_count"] = raw_content_str.count("endstream")
        streams = [len(s) for s in raw_content_str.split("stream")[1:]]
        features["avg_stream_size"] = sum(streams) / len(streams) if streams else 0
        features["xref_entries"] = raw_content_str.count("xref")
        features["name_obfuscations"] = raw_content_str.count("/Name")
        features["total_filters"] = raw_content_str.count("/Filter")
        features["nested_filters"] = raw_content_str.count("/FlateDecode")  # Example nested filter

        # Add stream_objects count
        features["stream_objects"] = raw_content_str.count("stream")  # Count stream objects if needed

        # Count keywords
        keywords = ["/JS", "/JavaScript", "/URI", "/Action", "/AA", "/OpenAction", "/launch",
                    "/submitForm", "/Acroform", "/XFA", "/JBig2Decode", "/Colors", "/Richmedia",
                    "/Trailer", "/Xref", "/Startxref"]
        for keyword in keywords:
            features[f"{keyword}_keywords"] = raw_content_str.count(keyword)

    except Exception as e:
        logging.error(f"Error extracting features from {pdf_path}: {e}")

    return features

def extract_embedded_files(doc):
    """
    Extract embedded file sizes from the PDF.
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

# Function to extract binary features (for non-PDF files like EXE, ZIP, etc.)
def extract_binary_features(file_path):
    features = {}
    
    try:
        with open(file_path, 'rb') as file:
            file_data = file.read()
        
        # Feature: File size
        features["file_size"] = os.path.getsize(file_path)
        
        # Feature: Entropy (measure of randomness in the file)
        features["entropy"] = calculate_entropy(file_data)
        
        # Check for executable file signatures (e.g., PE headers for Windows executables)
        features["is_executable"] = int(file_data[:2] == b'MZ')  # "MZ" is the PE header for executables
        
        # Check for ZIP file signature
        features["is_zip"] = int(file_data[:2] == b'PK')  # "PK" is the signature for ZIP files
        
        # Check for suspicious byte patterns (e.g., packed/obfuscated files)
        suspicious_patterns = [b"PE", b"PK", b"ZM", b"7z", b"exe", b"scripts"]
        features["suspicious_patterns"] = sum([file_data.find(pattern) != -1 for pattern in suspicious_patterns])
        
    except Exception as e:
        logging.error(f"Error inspecting binary features from {file_path}: {e}")
        features = {key: 0 for key in features.keys()}
    
    return features

# Calculate entropy of a file (used to detect packed/executable files)
def calculate_entropy(data):
    byte_freq = Counter(data)
    entropy = 0.0
    for byte, freq in byte_freq.items():
        prob = freq / len(data)
        entropy -= prob * (prob.bit_length()) if prob > 0 else 0
    return entropy

# Function to extract the contents of a ZIP file and process them
def extract_zip_contents(zip_path, temp_folder):
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_folder)
            print(f"Extracted files from {zip_path} to {temp_folder}")
            logging.debug(f"Extracted files from {zip_path} to {temp_folder}")
            
            for extracted_file in zip_ref.infolist():
                extracted_file_path = os.path.join(temp_folder, extracted_file.filename)
                if not os.path.isdir(extracted_file_path):  # Skip directories
                    features = extract_features_from_file(extracted_file_path)
                    yield features  # Yield features for each file

    except Exception as e:
        logging.error(f"Error extracting and processing ZIP contents from {zip_path}: {e}")

# Function to extract features from a single file (whether PDF, ZIP, EXE, etc.)
def extract_features_from_file(file_path):
    if file_path.lower().endswith('.pdf'):
        return extract_pdf_features(file_path)
    else:
        return extract_binary_features(file_path)

# Function to process a directory of files and extract features
def process_directory(directory_path, label):
    data = []
    for root, _, files in os.walk(directory_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if file_path.lower().endswith('.zip'):  # If it's a ZIP file, process its contents
                temp_folder = create_temporary_folder()  # Create temporary folder for extraction
                extracted_features = extract_zip_contents(file_path, temp_folder)
                for features in extracted_features:
                    features['label'] = label
                    data.append(features)
                cleanup_temporary_folder(temp_folder)  # Clean up after processing
            else:
                features = extract_features_from_file(file_path)
                features['label'] = label
                data.append(features)
    return data

# Function to save and display confusion matrix
def save_confusion_matrix(cm):
    fig, ax = plt.subplots(figsize=(8, 6))
    cax = ax.matshow(cm, cmap='Blues')
    fig.colorbar(cax)
    
    ax.set_xticks(np.arange(cm.shape[1]))
    ax.set_yticks(np.arange(cm.shape[0]))
    ax.set_xticklabels(['Legitimate', 'Malicious'])
    ax.set_yticklabels(['Legitimate', 'Malicious'])
    
    plt.xlabel('Predicted')
    plt.ylabel('True')
    plt.title('Confusion Matrix')
    
    # Save the image
    os.makedirs('training_images', exist_ok=True)  # Create folder if it doesn't exist
    plt.savefig('training_images/confusion_matrix.png')

def save_classification_report(cr, output_path):
    """
    Generates and saves a bar graph of the classification report for 'legitimate' and 'malicious' classes.

    :param report: The classification report as a dictionary.
    :param output_path: Path where the bar graph will be saved.
    """
    # Convert the report to a pandas DataFrame
    df = pd.DataFrame(cr).transpose()

    # Extract precision, recall, and f1-score
    categories = ['legitimate', 'malicious']
    precision = [df.at[cat, 'precision'] for cat in categories]
    recall = [df.at[cat, 'recall'] for cat in categories]
    f1_score = [df.at[cat, 'f1-score'] for cat in categories]

    # Plotting
    x = np.arange(len(categories))  # The label locations
    width = 0.2  # The width of the bars

    fig, ax = plt.subplots(figsize=(8, 6))

    # Create bars for precision, recall, and f1-score
    ax.bar(x - width, precision, width, label='Precision')
    ax.bar(x, recall, width, label='Recall')
    ax.bar(x + width, f1_score, width, label='F1 Score')

    # Add labels, title, and custom x-axis tick labels
    ax.set_xlabel('Class')
    ax.set_ylabel('Scores')
    ax.set_title('Classification Report: Legitimate vs Malicious')
    ax.set_xticks(x)
    ax.set_xticklabels(categories)
    ax.legend()

    # Save the figure as an image
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()

    print(f"Classification report graph saved at {output_path}")

def train_model(legitimate_dir, malicious_dir):
    # Process legitimate and malicious directories
    legitimate_data = process_directory(legitimate_dir, label=0)  # Label 0 for legitimate
    malicious_data = process_directory(malicious_dir, label=1)  # Label 1 for malicious
    
    # Combine data into a single list
    data = legitimate_data + malicious_data
    df = pd.DataFrame(data)  # Convert to DataFrame to ensure feature names are present
    
    # Split features (X) and labels (y)
    X = df.drop('label', axis=1)  # All columns except 'label' are features
    y = df['label']  # The label column is the target variable

    # Ensure column names are preserved by directly using 'FEATURE_COLUMNS'
    feature_columns = FEATURE_COLUMNS
    with open("feature_names.pkl", "wb") as f:
        pickle.dump(feature_columns, f)

    logging.info("Feature columns saved to 'feature_names.pkl'")

    # Ensure all columns are numeric and impute missing values (e.g., replace NaN with mean)
    X = X.apply(pd.to_numeric, errors='coerce')

    imputer = SimpleImputer(strategy='mean')  # Use mean strategy to fill missing values
    X_imputed = imputer.fit_transform(X)  # Transform the feature set

    # Apply SMOTE to balance the classes
    smote = SMOTE(random_state=42)
    X_resampled, y_resampled = smote.fit_resample(X_imputed, y)

    # Split the dataset into training and testing sets (80-20 split)
    X_train, X_test, y_train, y_test = train_test_split(X_resampled, y_resampled, test_size=0.2, random_state=42)

    # Initialize and train a Random Forest Classifier
    clf = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
    clf.fit(X_train, y_train)  # Train the model

    # Evaluate the model
    y_pred = clf.predict(X_test)  # Make predictions
    
    # Generate and save confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    save_confusion_matrix(cm)

    # Generate classification report
    cr = classification_report(y_test, y_pred, target_names=['Legitimate', 'Malicious'], output_dict=True)
    save_classification_report(cr, 'training_images/classification_report.png')

    # Save the trained model to a pickle file
    with open('malicious_classifier.pkl', 'wb') as model_file:
        pickle.dump(clf, model_file)

    logging.info("Model saved as 'malicious_classifier.pkl'")

    return clf  # Return the trained model


if __name__ == '__main__':
    legitimate_dir = 'training_files/Legitimate'
    malicious_dir = 'training_files/Malicious'
    
    model = train_model(legitimate_dir, malicious_dir)
    print("Model saved as 'malicious_classifier.pkl'")
