#!/bin/bash

# Install the requirements
echo "Installing dependencies from requirements.txt..."
pip install -r requirements.txt

# Hardcoded Python file names
TRAINING="training.py"
PREDICTION="predicition.py"

# Check if the Python files exist
if [ ! -f "$TRAINING" ]; then
  echo "Error: $TRAINING not found!"
  exit 1
fi

if [ ! -f "$PREDICTION" ]; then
  echo "Error: $PREDICTION not found!"
  exit 1
fi

# Run the Python files
echo "Running $TRAINING..."
python "$TRAINING"

echo "Running $PREDICTION..."
python "$PREDICTION"

echo "Script execution completed."
