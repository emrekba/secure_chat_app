# Git Push Kılavuzu

## 1. Tüm Dosyaları Ekleyin

```bash
cd /home/emre/Masaüstü/secure_chat_app
git add .
```

## 2. Commit Yapın

```bash
git commit -m "Güvenli chat uygulaması - LSB steganografi ve DES şifreleme ile"
```

## 3. Remote Repository Ekleyin (GitHub/GitLab vb.)

Eğer GitHub'da repository oluşturduysanız:

```bash
git remote add origin https://github.com/KULLANICI_ADI/REPO_ADI.git
```

veya SSH ile:

```bash
git remote add origin git@github.com:KULLANICI_ADI/REPO_ADI.git
```

## 4. Push Yapın

```bash
git push -u origin master
```

veya main branch kullanıyorsanız:

```bash
git branch -M main
git push -u origin main
```

## Hızlı Komutlar (Tümünü Birden)

```bash
cd /home/emre/Masaüstü/secure_chat_app
git add .
git commit -m "Güvenli chat uygulaması"
git remote add origin https://github.com/KULLANICI_ADI/REPO_ADI.git
git push -u origin master
```

## Notlar

- İlk kez push yapıyorsanız GitHub/GitLab'da repository oluşturmanız gerekir
- Eğer zaten bir remote varsa, `git remote -v` ile kontrol edin
- Remote'u değiştirmek için: `git remote set-url origin YENI_URL`

