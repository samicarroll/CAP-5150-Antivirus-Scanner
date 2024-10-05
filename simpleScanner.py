"""
PDF Simple Scanner

This Python script scans PDF files in a specified directory for potential malicious threats. 
It checks for:

1. Suspicious metadata: Looks for specific keywords in the PDF's metadata that may indicate malicious intent.
2. Embedded JavaScript: Detects if any JavaScript code is embedded within the PDF, which is commonly used by malicious PDFs.
3. Suspicious content: Searches the text content of the PDF for known keywords related to malware.

Libraries Used:
- PyPDF2: A library to read PDF files and extract metadata and page contents.
- pdfminer.six: A library to extract text from PDF files.

Instructions:
1. Ensure you have Python installed.
2. Install the required libraries using:
   pip/pip3 install PyPDF2 pdfminer.six
3. Run the script and provide the directory containing the PDF files to scan.
    python/python3 simpleScanner.py
    
Note: This program is a simple scanner; will produce false positives and HAS NOT been tested on
known malicious files. This file is used to test concepts of PyPDF2 and pdfminer.six libraries. 
"""

import os
import re
import PyPDF2
from pdfminer.high_level import extract_text


"""
Check the PDF's metadata for suspicious keywords.

Args:
- pdf_path (str): Path to the PDF file.

Returns:
- bool: True if suspicious metadata is found, False otherwise.
"""
def has_suspicious_metadata(pdf_path):
    suspicious_keywords = ['malicious', 'attack', 'virus']
    try:
        with open(pdf_path, "rb") as file:
            reader = PyPDF2.PdfReader(file)
            metadata = reader.metadata
            
            # Check for suspicious metadata keys
            if metadata:
                for key, value in metadata.items():
                    for keyword in suspicious_keywords:
                        if re.search(rf'(?i){keyword}', str(value)):
                            print(f"[!] Suspicious metadata found in {pdf_path}:")
                            print(f"    - Key: {key}")
                            print(f"    - Value: {value}")
                            print(f"    - Keyword: {keyword}\n")
                            return True
    except Exception as e:
        print(f"Error reading metadata: {e}")
    return False


"""
Check for embedded JavaScript in the PDF.

Args:
- pdf_path (str): Path to the PDF file.

Returns:
- bool: True if embedded JavaScript is found, False otherwise.
"""
def contains_embedded_javascript(pdf_path):
    try:
        with open(pdf_path, "rb") as file:
            reader = PyPDF2.PdfReader(file)
            for page in reader.pages:
                if '/JS' in page:
                    print(f"[!] Embedded JavaScript found in {pdf_path}\n")
                    return True
    except Exception as e:
        print(f"Error checking for embedded JavaScript: {e}")
    return False


"""
Search the PDF's text content for suspicious keywords.

Args:
- pdf_path (str): Path to the PDF file.

Returns:
- bool: True if suspicious content is found, False otherwise.
"""
def check_for_suspicious_content(pdf_path):
    suspicious_keywords = ['malware', 'trojan', 'ransomware', 'phishing']
    try:
        text = extract_text(pdf_path)
        # Check for suspicious keywords in the text
        for keyword in suspicious_keywords:
            if re.search(rf'(?i){keyword}', text):
                print(f"[!] Suspicious content found in {pdf_path}:")
                print(f"    - Keyword: {keyword}\n")
                return True
    except Exception as e:
        print(f"Error extracting text: {e}")
    return False


"""
Scan a single PDF file for potential threats.

Args:
- pdf_path (str): Path to the PDF file.
"""
def scan_pdf(pdf_path):
    print(f"Scanning {pdf_path}...")
    potential_threats = False
    if (has_suspicious_metadata(pdf_path) or
            contains_embedded_javascript(pdf_path) or
            check_for_suspicious_content(pdf_path)):
        potential_threats = True
    
    if potential_threats:
        print(f"[!] Potential threat detected in {pdf_path}\n")
    else:
        print(f"[✓] {pdf_path} appears to be safe.\n")


"""
Scan all PDF files in a specified directory.

Args:
- directory (str): Path to the directory containing PDF files.
"""
def scan_directory(directory):
    print(f"Scanning directory: {directory}\n")
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith('.pdf'):
                scan_pdf(os.path.join(root, file))
    print("Scan completed.")


if __name__ == "__main__":
    # Prompt user for the directory to scan
    directory_to_scan = input("Enter the directory to scan for PDF files: ")
    scan_directory(directory_to_scan)
