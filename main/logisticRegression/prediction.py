import os
import fitz  # PyMuPDF
import pickle
import xml.etree.ElementTree as ET
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import numpy as np


# Load the pre-trained model and vectorizer
model_filename = 'logistic_regression_model.pkl'
vectorizer_filename = 'vectorizer.pkl'

with open(model_filename, 'rb') as model_file:
    model = pickle.load(model_file)

with open(vectorizer_filename, 'rb') as vectorizer_file:
    vectorizer = pickle.load(vectorizer_file)

# Function to extract text using PyMuPDF (fitz)
def extract_text_with_pymupdf(pdf_path):
    text = ""
    try:
        doc = fitz.open(pdf_path)
        for page in doc:
            text += page.get_text("text")
    except Exception as e:
        print(f"Error extracting text with PyMuPDF: {e}")
    return text

# Function to extract XFA (XML Forms Architecture) content from PDF
def extract_xfa_content(pdf_path):
    text = ""
    try:
        doc = fitz.open(pdf_path)
        for page in doc:
            xfa_objects = page.get_text("xml")  # Extract XML data from the PDF
            if "<xdp:xdp" in xfa_objects:  # Check if it contains XFA
                print("XFA data found in this PDF.")
                tree = ET.ElementTree(ET.fromstring(xfa_objects))
                root = tree.getroot()
                for elem in root.iter():
                    text += ET.tostring(elem, encoding='utf-8').decode('utf-8')  # Extract all XML data
            else:
                print("No XFA data found in this page.")
    except Exception as e:
        print(f"Error extracting XFA content: {e}")
    return text

# Function to extract text from the PDF
def extract_text_from_pdf(pdf_path):
    print(f"Extracting text from {pdf_path} using PyMuPDF...")
    text = extract_text_with_pymupdf(pdf_path)
    
    if not text:  # If no text is extracted, try extracting XFA content
        print(f"No text extracted using PyMuPDF. Attempting XFA extraction...")
        text = extract_xfa_content(pdf_path)

    return text

# Function to make predictions on the PDF file
def predict_pdf(pdf_path):
    print(f"Processing PDF: {pdf_path}")
    
    # Extract text from the PDF
    extracted_content = extract_text_from_pdf(pdf_path)
    
    if not extracted_content:
        print(f"No text extracted from {pdf_path}. Unable to classify. Assuming the file is malicious.")
        # If no text is extracted, classify it as malicious
        print(f"The file {pdf_path} is predicted to be Malicious (Assumed).")
        return
    
    # Vectorize the extracted text
    X = vectorizer.transform([extracted_content])
    
    # Make prediction
    prediction = model.predict(X)
    
    # Output result
    if prediction[0] == 'malicious':
        print(f"The file {pdf_path} is predicted to be Malicious.")
    else:
        print(f"The file {pdf_path} is predicted to be Legitimate.")

# Get the file path from user input and convert it to an absolute path
relative_pdf_path = input("Enter the path to the PDF file: ")

# Convert relative path to absolute path
pdf_path = os.path.abspath(relative_pdf_path)

# Check if the file exists before proceeding
if not os.path.isfile(pdf_path):
    print(f"The file {pdf_path} does not exist. Please check the path and try again.")
else:
    # Proceed with prediction
    predict_pdf(pdf_path)
