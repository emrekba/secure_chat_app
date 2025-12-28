#!/bin/bash

# Client'ı virtual environment ile çalıştır

cd "$(dirname "$0")"
source venv/bin/activate
python3 client.py

