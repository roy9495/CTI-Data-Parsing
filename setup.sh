#!/bin/bash

echo "[*] Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "[*] Installing requirements..."
pip install -r requirements.txt

echo "[*] Creating directories..."
mkdir -p output logs

echo "[*] Setup complete."
