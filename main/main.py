"""
PDF Malware Scanner with Machine Learning

This Python script scans PDF files in a specified directory for potential malicious threats 
using a machine learning model. It checks for:

1. Suspicious metadata.
2. Embedded JavaScript.
3. Suspicious content.
4. Classifies the PDF as 'malicious' or 'safe' using a pre-trained machine learning model.

Libraries Used:
- PyPDF2: A library to read PDF files and extract metadata and page contents.
- pdfminer.six: A library to extract text from PDF files.
- scikit-learn: A library for machine learning.
- matplotlib: A library for creating visualizations.

Instructions:
1. Run the script and provide the directory containing the PDF files to scan.
    python/python3 pdf_malware_scanner.py

"""

import os
import re
import time
import pickle
import numpy as np
import pandas as pd
import PyPDF2     #reading, writing, merging/splitting, manipulating pages, adding content, encrypting and decrypting PDFs
from pdfminer.high_level import extract_text #extract and analyze text data in PDFs
import matplotlib.pyplot as plt

# Define the directory where the model and feature names are stored
model_directory = 'model_files'

# Load the pre-trained machine learning model from a file
with open(os.path.join(model_directory, 'malware_model.pkl'), 'rb') as model_file:
    # Load the model from the pickle file
    model = pickle.load(model_file)
    # Confirm model type
    print(f"Model Loaded: {type(model)}")

# Global variables to hold feature names and counts of malicious/legitimate files
feature_names = []
malicious_count = 0
legitimate_count = 0

def extract_features(pdf_path):
    """
    Extracts features from a given PDF file.

    Args:
        pdf_path (str): Path to the PDF file.

    Returns:
        np.ndarray: A feature vector representing various characteristics of the PDF.
    """
    # Initialize a feature vector with zeros; length should match the expected number of features
    features = np.zeros(54)  # Adjust size based on model requirements

    # Open the PDF file for reading
    try:
        with open(pdf_path, "rb") as file:
            # Read the PDF file
            reader = PyPDF2.PdfReader(file)
            # Extract PDF metadata
            metadata = reader.metadata 
            
            # Extract metadata features
            if metadata:
                for i, key in enumerate(metadata.keys()):
                    # Length of each metadata value
                    features[i] = len(str(metadata[key]))
                    if i + len(metadata) < 54:
                        # Length of metadata keys
                        features[i + len(metadata)] = len(key)

                # Check for suspicious metadata fields
                suspicious_keys = ['Producer', 'Creator', 'Author']
                for i, key in enumerate(suspicious_keys):
                    features[i + len(metadata)] = len(metadata.get(key, ''))

            # Extract content features from the PDF
            # Use pdfminer to extract text
            text = extract_text(file)
            # Length of the text content
            features[0] = len(text)
            # Count occurrences of the word 'malware'
            features[1] = text.count('malware')
            # Count occurrences of the word 'virus'
            features[2] = text.count('virus')
            # Count occurrences of embedded JavaScript
            features[3] = text.count('<script>')
            # Count occurrences of URLs
            features[4] = text.count('http')
            # Count occurrences of secure URLs
            features[5] = text.count('https')

            # Count the number of pages in the PDF
            # Total number of pages
            features[6] = len(reader.pages)
            
            # Count unique words in the text
            unique_words = set(text.split())
            # Number of unique words
            features[7] = len(unique_words)
            
            # Count number of embedded files, if applicable
            if hasattr(reader, 'embedded_files'):
                # Number of embedded files
                features[8] = len(reader.embedded_files) 

            print(f"Extracted features for {pdf_path}: {len(features)}")
    except Exception as e:
        # Log any errors that occur
        print(f"Error extracting features from {pdf_path}: {e}")

    return features  # Return the feature vector

def scan_pdf(pdf_path):
    """
    Scans a single PDF file for malicious content using the pre-trained model.

    Args:
        pdf_path (str): Path to the PDF file to scan.
    """
    global malicious_count, legitimate_count  # Use global counts

    # Extract features from the PDF
    features = extract_features(pdf_path)

    # Convert the feature vector to a DataFrame for prediction
    features_df = pd.DataFrame(features.reshape(1, -1), columns=feature_names)

    # Make predictions using the model
    prediction = model.predict(features_df)

    # Update counts based on prediction result
    if prediction[0] == 1:
        # Malware detected
        result = "[⚠️] Malware Detected" 
        
        # Increment malicious count
        malicious_count += 1 
    else:
        # File is safe - no malicious content detected
        result = "[✓] File is Legitimate" 
        
         # Increment legitimate count
        legitimate_count += 1

    # Print the prediction results in a user-friendly format
    print(f"\n{'-' * 40}")
    
    print(f"Scanning file: {pdf_path}...")
    
    print(f"Extracted features: {len(features)}")
    
    print(f"{'-' * 40}")
    
    print(f"--- PDF Scan Result for: {pdf_path} ---")
    
    print(f"Prediction: {result}")
    
    print(f"{'-' * 40}")

def scan_directory(directory):
    """
    Scans all PDF files in the specified directory and its subdirectories.

    Args:
        directory (str): The directory to scan for PDF files.
    """
    print(f"\n--- Scanning Directory: {directory} ---")
    
    # Traverse the directory and its subdirectories
    for root, dirs, files in os.walk(directory):
        for file in files:
             # Process only PDF files
            if file.endswith('.pdf'):
                 # Scan the PDF file
                scan_pdf(os.path.join(root, file))


def plot_results():
    """
    Plots the results of the PDF scan as a bar graph.
    """
    # Create a bar graph of the scan results
    # Categories for the bar graph
    labels = ['Malicious', 'Legitimate']
    
    # Corresponding data
    counts = [malicious_count, legitimate_count]
    
    # Create bars for each category
    plt.bar(labels, counts, color=['red', 'green'])
    
    # Title of the graph
    plt.title('PDF Scan Results')
    
    # X-axis label
    plt.xlabel('Classification')
    
    # Y-axis label
    plt.ylabel('Count')
    
    # Set y-axis limit to accommodate counts
    plt.ylim(0, max(counts) + 1)

    # Annotate the bars with counts
    for index, value in enumerate(counts):
        plt.text(index, value, str(value), ha='center')

    # Display the plot
    plt.show()


if __name__ == "__main__":
    # Load feature names from the trained model's saved file
    with open(os.path.join(model_directory, 'feature_names.pkl'), 'rb') as fn_file:
        feature_names = pickle.load(fn_file)

    # Prompt user for the directory to scan
    directory_to_scan = input("Enter the directory to scan for PDF files: ")
    
    # Start scanning the specified directory
    scan_directory(directory_to_scan) 

    # Plot the results after scanning
    plot_results() 
