#!/bin/sh

# Add debugging information
echo "Current directory: $(pwd)"
echo "Python path: $PYTHONPATH"
echo "Directory contents:"
ls -la /opt/opencti-connector-socradar/src

# Directly execute python script
cd /opt/opencti-connector-socradar
python3 src/main.py
