# Güvenli Chat Uygulaması - Kullanım Kılavuzu

## Kurulum

1. Gerekli Python paketlerini yükleyin:
```bash
pip install -r requirements.txt
```

## Çalıştırma

### 1. Server'ı Başlatın

Terminal'de:
```bash
python3 server.py
```

Server varsayılan olarak `localhost:8888` adresinde dinlemeye başlar.

### 2. Client'ı Başlatın

Yeni bir terminal'de:
```bash
python3 client.py
```

Birden fazla client açarak farklı kullanıcılarla test edebilirsiniz.

## Kullanım Adımları

### Kayıt Olma

1. Client arayüzünde "Kayıt Ol" sekmesine gidin
2. Kullanıcı adı ve şifre girin
3. "Seç" butonuna tıklayarak bir fotoğraf seçin (PNG, JPG, JPEG, BMP formatları desteklenir)
4. "Kayıt Ol" butonuna tıklayın
5. Sistem şifrenizi LSB steganografi ile fotoğrafa gömer ve server'a gönderir

### Giriş Yapma

1. "Giriş Yap" sekmesine gidin
2. Kayıt olduğunuz kullanıcı adı ve şifreyi girin
3. "Giriş Yap" butonuna tıklayın
4. Başarılı girişten sonra "Chat" sekmesi açılır

### Mesaj Gönderme

1. Chat sekmesinde kullanıcı listesinden alıcıyı seçin veya manuel olarak alıcı adını girin
2. Mesajınızı yazın
3. "Gönder" butonuna tıklayın veya Enter'a basın
4. Mesajınız DES ile şifrelenir ve server'a gönderilir
5. Server mesajı alıcının şifresi ile yeniden şifreler ve gönderir

### Kullanıcı Listesi

- "Yenile" butonuna tıklayarak online/offline kullanıcıları görebilirsiniz
- 🟢 = Online kullanıcı
- 🔴 = Offline kullanıcı

### Offline Mesajlar

- Offline kullanıcılara mesaj gönderebilirsiniz
- Mesajlar server'da bekletilir ve kullanıcı giriş yaptığında otomatik olarak gönderilir

## Güvenlik Özellikleri

1. **LSB Steganografi**: Şifreler fotoğrafların LSB (Least Significant Bit) katmanına gömülür
2. **DES Şifreleme**: Tüm mesajlar DES algoritması ile şifrelenir
3. **Çift Şifreleme**: Mesajlar gönderenin şifresi ile şifrelenir, server'da çözülür ve alıcının şifresi ile yeniden şifrelenir

## Notlar

- Server'ı kapatmadan önce tüm client'ları kapatın
- Fotoğraflar `server_data/photos/` ve `server_data/embedded_photos/` klasörlerinde saklanır
- Geçici dosyalar `temp/` klasöründe oluşturulur ve otomatik silinir

