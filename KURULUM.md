# Kurulum Talimatları - Kali Linux

## Gerekli Sistem Paketleri

Kali Linux'ta önce şu paketleri yüklemeniz gerekiyor:

```bash
sudo apt update
sudo apt install -y python3-tk python3-venv
```

## Python Paketlerini Kurma

### Yöntem 1: Virtual Environment (Önerilen)

```bash
cd /home/emre/Masaüstü/secure_chat_app
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Yöntem 2: Sistem Paketleri (Alternatif)

```bash
cd /home/emre/Masaüstü/secure_chat_app
./install_packages.sh
```

## Çalıştırma

### Server
```bash
python3 server.py
# veya virtual environment ile:
source venv/bin/activate
python3 server.py
```

### Client
```bash
python3 client.py
# veya virtual environment ile:
source venv/bin/activate
python3 client.py
```

## Notlar

- `python3-tk`: Tkinter GUI kütüphanesi için gerekli
- `python3-venv`: Virtual environment oluşturmak için gerekli
- Eğer sudo kullanmak istemiyorsanız, `install_packages.sh` scriptini kullanabilirsiniz

