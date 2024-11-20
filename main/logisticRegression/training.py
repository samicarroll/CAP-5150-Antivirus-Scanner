import os
import zipfile
import shutil
import logging
from collections import Counter
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from imblearn.over_sampling import SMOTE
from sklearn.feature_extraction.text import TfidfVectorizer
import matplotlib.pyplot as plt
import pickle
import numpy as np
import fitz  # PyMuPDF

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# Function to create a temporary folder for extracting ZIP contents
def create_temporary_folder():
    temp_folder = 'temp'
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

def extract_pdf_text(pdf_path):
    """
    Extracts raw text from a PDF.
    """
    text = ""
    try:
        doc = fitz.open(pdf_path)
        for page in doc:
            text += page.get_text("text")
    except Exception as e:
        logging.error(f"Error extracting text from {pdf_path}: {e}")
    return text

# Function to extract contents of a ZIP file and process them
def extract_zip_contents(zip_path, temp_folder):
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_folder)
            print(f"Extracted files from {zip_path} to {temp_folder}")
            logging.debug(f"Extracted files from {zip_path} to {temp_folder}")
            
            for extracted_file in zip_ref.infolist():
                extracted_file_path = os.path.join(temp_folder, extracted_file.filename)
                if not os.path.isdir(extracted_file_path):  # Skip directories
                    if extracted_file_path.lower().endswith('.pdf'):
                        text = extract_pdf_text(extracted_file_path)  # Process PDF files
                        yield text  # Yield text content for each file

    except Exception as e:
        logging.error(f"Error extracting and processing ZIP contents from {zip_path}: {e}")

# Function to process a directory of files and extract text
def process_directory(directory_path, label, limit=None):
    data = []
    pdf_count = 0  # Counter to keep track of how many PDFs we've processed
    for root, _, files in os.walk(directory_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            
            # If it's a ZIP file, process its contents
            if file_path.lower().endswith('.zip'):  
                temp_folder = create_temporary_folder()  # Create temporary folder for extraction
                extracted_text = extract_zip_contents(file_path, temp_folder)
                for text in extracted_text:
                    if text:
                        data.append((text, label))  # Append text and label to the data
                        pdf_count += 1
                        if limit and pdf_count >= limit:
                            break  # Stop if we've reached the limit
                cleanup_temporary_folder(temp_folder)  # Clean up after processing

            # If it's a direct PDF, process it
            elif file_path.lower().endswith('.pdf'):
                text = extract_pdf_text(file_path)
                if text:
                    data.append((text, label))  # Append text and label to the data
                    pdf_count += 1
                    if limit and pdf_count >= limit:
                        break  # Stop if we've reached the limit
        if limit and pdf_count >= limit:
            break  # Stop walking the directory if we've reached the limit
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
    plt.close()

def save_classification_report(cr, output_path):
    """
    Generates and saves a bar graph of the classification report for 'legitimate' and 'malicious' classes.
    """
    # Convert the report to a pandas DataFrame
    df = pd.DataFrame(cr).transpose()  # .transpose() to flip rows and columns

    # Ensure the classes are labeled 'Legitimate' and 'Malicious' in the classification report
    categories = ['legitimate', 'malicious']  # Use lowercase to match classification report output

    # Check if the classification report contains both 'legitimate' and 'malicious' keys
    missing_categories = [cat for cat in categories if cat not in df.index]

    if missing_categories:
        print(f"Warning: Missing categories in classification report: {missing_categories}")
        categories = [cat for cat in categories if cat not in missing_categories]

    # Now extract the precision, recall, and f1-score for each category dynamically
    precision = [df.at[cat, 'precision'] if cat in df.index else 0 for cat in categories]
    recall = [df.at[cat, 'recall'] if cat in df.index else 0 for cat in categories]
    f1_score = [df.at[cat, 'f1-score'] if cat in df.index else 0 for cat in categories]

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
    legitimate_data = process_directory(legitimate_dir, label="legitimate", limit=10)  # Limit to first 10 legitimate PDFs
    malicious_data = process_directory(malicious_dir, label="malicious", limit=10)  # All 10 malicious PDFs
    
    print(f"Legitimate data count: {len(legitimate_data)}")
    print(f"Malicious data count: {len(malicious_data)}")

    if len(legitimate_data) == 0 or len(malicious_data) == 0:
        raise ValueError("Both legitimate and malicious data are required for model training.")

    # Combine data
    data = legitimate_data + malicious_data
    df = pd.DataFrame(data, columns=['text', 'label'])

    # Preprocess the text data
    X_text = df['text'].apply(lambda x: x.lower()).tolist()  # Simple lowercase text preprocessing
    y = df['label'].values

    # Vectorize the text data using TF-IDF
    vectorizer = TfidfVectorizer(stop_words='english', max_features=5000)
    X = vectorizer.fit_transform(X_text)

    # Split the dataset into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Train the Logistic Regression model
    model = LogisticRegression(max_iter=1000)
    model.fit(X_train, y_train)

    # Make predictions on the test set
    y_pred = model.predict(X_test)

    # Evaluate the model
    cm = confusion_matrix(y_test, y_pred, labels=['legitimate', 'malicious'])
    print("Confusion Matrix:\n", cm)
    print("\nClassification Report:\n", classification_report(y_test, y_pred, target_names=['legitimate', 'malicious']))

    # Save the model and vectorizer
    with open('logistic_regression_model.pkl', 'wb') as model_file:
        pickle.dump(model, model_file)
    with open('vectorizer.pkl', 'wb') as vectorizer_file:
        pickle.dump(vectorizer, vectorizer_file)

    # Save the confusion matrix and classification report as images
    save_confusion_matrix(cm)
    save_classification_report(classification_report(y_test, y_pred, output_dict=True), 'training_images/classification_report.png')

    print("Model and vectorizer saved as 'logistic_regression_model.pkl' and 'vectorizer.pkl'")

# Main function to be executed
def main():
    legitimate_dir = r'training_files/Legitimate' 
    malicious_dir = r'training_files/Malicious' 
    train_model(legitimate_dir, malicious_dir)

# Ensure that the main function is called when the script is executed directly
if __name__ == "__main__":
    main()
