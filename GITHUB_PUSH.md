# GitHub Push - Kimlik Doğrulama Çözümü

## Seçenek 1: Personal Access Token (PAT) Kullanma

### 1. GitHub'da Personal Access Token Oluşturun

1. GitHub'a giriş yapın
2. Sağ üst köşedeki profil resminize tıklayın
3. **Settings** → **Developer settings** → **Personal access tokens** → **Tokens (classic)**
4. **Generate new token** → **Generate new token (classic)** tıklayın
5. Token için bir isim verin (örn: "secure_chat_app")
6. **Expiration** seçin (90 gün veya istediğiniz süre)
7. **repo** seçeneğini işaretleyin (tüm repo seçeneklerini seçebilirsiniz)
8. **Generate token** butonuna tıklayın
9. **ÖNEMLİ:** Token'ı kopyalayın (bir daha gösterilmeyecek!)

### 2. Token ile Push Yapın

```bash
cd /home/emre/Masaüstü/secure_chat_app

# Remote URL'i token ile güncelleyin
git remote set-url origin https://TOKEN@github.com/emrekba/secure_chat_app.git

# Push yapın (username olarak GitHub kullanıcı adınızı, password olarak token'ı girin)
git push -u origin main
```

**Not:** Token'ı URL'de kullanmak güvenli değil. Daha iyi yöntem:

```bash
# Sadece push yaparken token isteyecek
git push -u origin main
# Username: emrekba
# Password: TOKEN_BURAYA
```

### 3. Git Credential Helper Kullanma (Önerilen)

```bash
# Credential helper'ı ayarlayın
git config --global credential.helper store

# İlk push'ta token'ı girin, sonra otomatik hatırlanacak
git push -u origin main
# Username: emrekba
# Password: TOKEN_BURAYA
```

---

## Seçenek 2: SSH Key Kullanma (Daha Güvenli)

### 1. SSH Key Oluşturun

```bash
ssh-keygen -t ed25519 -C "your_email@example.com"
# Enter'a basın (default location)
# Passphrase isteyebilir (opsiyonel)
```

### 2. SSH Key'i GitHub'a Ekleyin

```bash
# Public key'i gösterin
cat ~/.ssh/id_ed25519.pub
```

1. GitHub → **Settings** → **SSH and GPG keys** → **New SSH key**
2. Key'i yapıştırın ve kaydedin

### 3. Remote URL'i SSH'a Çevirin

```bash
cd /home/emre/Masaüstü/secure_chat_app
git remote set-url origin git@github.com:emrekba/secure_chat_app.git
git push -u origin main
```

---

## Hızlı Çözüm (PAT ile)

1. GitHub'da token oluşturun (yukarıdaki adımlar)
2. Terminal'de:

```bash
cd /home/emre/Masaüstü/secure_chat_app
git push -u origin main
```

3. İstendiğinde:
   - **Username:** emrekba
   - **Password:** Token'ınızı yapıştırın

4. Credential helper ile kaydetmek için:
```bash
git config --global credential.helper store
```

