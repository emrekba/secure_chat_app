#!/bin/bash

# Alternatif kurulum scripti (--break-system-packages ile)
# DİKKAT: Bu yöntem sistem Python'unu etkileyebilir

echo "Paketler kuruluyor (sistem paketleri koruması devre dışı)..."
pip install --break-system-packages -r requirements.txt

echo ""
echo "Kurulum tamamlandı!"
echo "Artık direkt çalıştırabilirsiniz:"
echo "  python3 server.py"
echo "  python3 client.py"

