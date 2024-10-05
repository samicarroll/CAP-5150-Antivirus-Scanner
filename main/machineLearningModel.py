"""
Malware Detection Model Training

This script trains a machine learning model to classify files as either 
malicious or legitimate based on various features extracted from the 
files. The model is built using the Random Forest algorithm.

Steps performed in the script:
1. Load a CSV dataset containing features of files and a target variable indicating whether each file is legitimate or not.
2. Preprocess the data by separating features and the target variable, and dropping unnecessary columns.
3. Split the data into training and testing sets.
4. Train a Random Forest classifier on the training data.
5. Evaluate the model's performance using a confusion matrix and classification report.
6. Save the trained model and feature names to files for future use.

Datasource: https://www.kaggle.com/datasets/dscclass/malware?resource=download
"""

import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import pickle
from tqdm import tqdm
import matplotlib.pyplot as plt

# Create a directory for saving models if it does not exist
save_directory = 'model_files'
if not os.path.exists(save_directory):
    os.makedirs(save_directory)
    print(f"Created directory: {save_directory}")

# Load the dataset with a progress bar
print("Loading the dataset...")

# Count total rows in the file to set up the progress bar
with open('malware.csv') as f:
    total_rows = sum(1 for _ in f)

print(f"Total rows to read: {total_rows}")

# Initialize an empty DataFrame to hold the entire dataset
data = pd.DataFrame()

# Number of rows to read at once to manage memory
chunk_size = 10000

# Read the CSV file in chunks to avoid loading the entire file into memory at once
for chunk in tqdm(pd.read_csv('malware.csv', delimiter='|', chunksize=chunk_size), total=total_rows // chunk_size):
    # Concatenate each chunk to the main DataFrame
    data = pd.concat([data, chunk])  

print("Dataset loaded successfully.")
# Display the first few rows of the loaded dataset
print(data.head())

# Preprocessing the data
print("Preprocessing the data...")

# Separate features (X) from the target variable (y)
# remove non-essential columns
X = data.drop(columns=['Name', 'md5', 'legitimate'])

# Map the target variable to meaningful labels
y = data['legitimate'].map({0: 'legitimate', 1: 'malicious'})

print("Features and target variable separated.")

# Save feature names to a pickle file for future reference
# Extract feature names
feature_names = X.columns

with open(os.path.join(save_directory, 'feature_names.pkl'), 'wb') as feature_file:
    pickle.dump(feature_names, feature_file)

print("Feature names saved successfully.")

# Split the dataset into training (80%) and testing (20%) sets
print("Splitting the dataset into training and testing sets...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print(f"Training set size: {len(X_train)} | Testing set size: {len(X_test)}")

# Initialize the Random Forest classifier
model = RandomForestClassifier()

# Train the model on the training data
print("Training the model...")
model.fit(X_train, y_train)
print("Model training completed.")

# Make predictions on the test set
print("Making predictions on the test set...")
y_pred = model.predict(X_test)

# Evaluate the model's performance
print("Evaluating the model performance...")
# Create confusion matrix
conf_matrix = confusion_matrix(y_test, y_pred, labels=['legitimate', 'malicious'])
print("Confusion Matrix:")
print(conf_matrix)

# Generate a classification report to assess the model's performance
class_report = classification_report(y_test, y_pred, target_names=['legitimate', 'malicious'], output_dict=True)
# Convert report to DataFrame for better formatting
report_df = pd.DataFrame(class_report).transpose()

print("\nClassification Report:")
# Display selected metrics: precision, recall, F1-score, and support
print(report_df[['precision', 'recall', 'f1-score', 'support']])

# Plotting the classification report metrics
plt.figure(figsize=(10, 6))
# Plot all but the 'accuracy' row
report_df[['precision', 'recall', 'f1-score']].iloc[:-1].plot(kind='bar', rot=0)
plt.title('Classification Report Metrics')
plt.ylabel('Scores')
plt.xticks(range(len(report_df.index[:-1])), report_df.index[:-1], rotation=0)
 # Set y-axis limit for clarity
plt.ylim(0, 1.5)
plt.grid(axis='y')
plt.legend(loc='best')
plt.tight_layout()
# Display the plot
plt.show()

# Save the trained model to a file using pickle for future use
print("Saving the trained model to 'malware_model.pkl'...")
with open(os.path.join(save_directory, 'malware_model.pkl'), 'wb') as model_file:
    # Serialize the model to a file
    pickle.dump(model, model_file)
print("Model saved successfully.")

# Comments on the evaluation results:
# The confusion matrix shows the counts of correctly and incorrectly classified samples.
# The formatted classification report provides detailed metrics:
# - Precision indicates the accuracy of positive predictions.
# - Recall measures the model's ability to find all positive samples.
# - F1-score is the mean of precision and recall, balancing both.
# A high accuracy and a good balance between precision and recall are desirable for a malware detection model.