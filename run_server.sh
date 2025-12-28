#!/bin/bash

# Server'ı virtual environment ile çalıştır

cd "$(dirname "$0")"
source venv/bin/activate
python3 server.py

