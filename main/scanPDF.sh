#!/bin/bash

# This script may have to be altered to satisfy your system
# requirements. For example, this script uses pip3 to install requirements
# and python3 to run the Python scripts. The script may need to be altered 
# to use pip and python instead. 

#------uncomment the line below to enable debugging------#
# set -x

# Check if requirements.txt exists
if [ -f requirements.txt ]; then
    echo "Requirements file found. Installing dependencies from requirements.txt..."
    pip3 install -r requirements.txt
    echo "Dependencies installed successfully."
else
    echo "requirements.txt not found!"
    exit 1
fi

# Run the machine learning model script
echo "--------------------------------------------------"
echo "Running machineLearningModel.py..."
python3 machineLearningModel.py

# Check if the previous command was successful
if [ $? -ne 0 ]; then
    echo "Error: Failed to run machineLearningModel.py"
    exit 1
fi

# Run the main script
echo "--------------------------------------------------"
echo "Running main.py..."
python3 main.py

# Check if the previous command was successful
if [ $? -ne 0 ]; then
    echo "Error: Failed to run main.py"
    exit 1
fi

echo "--------------------------------------------------"
echo "All scripts executed successfully."
