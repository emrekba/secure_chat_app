#!/bin/bash

# Güvenli Chat Uygulaması - Kurulum Scripti

echo "Güvenli Chat Uygulaması kurulumu başlatılıyor..."

# Virtual environment oluştur
echo "Virtual environment oluşturuluyor..."
python3 -m venv venv

# Virtual environment'ı aktif et
echo "Virtual environment aktif ediliyor..."
source venv/bin/activate

# Paketleri yükle
echo "Gerekli paketler yükleniyor..."
pip install --upgrade pip
pip install -r requirements.txt

echo ""
echo "Kurulum tamamlandı!"
echo ""
echo "Kullanım:"
echo "1. Virtual environment'ı aktif edin: source venv/bin/activate"
echo "2. Server'ı başlatın: python3 server.py"
echo "3. Client'ı başlatın: python3 client.py"
echo ""
echo "Virtual environment'tan çıkmak için: deactivate"

