"""
DES (Data Encryption Standard) Şifreleme Modülü
Mesajları şifreleme ve çözme işlemleri
"""
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import base64


def encrypt_message(message, password):
    """
    Mesajı DES ile şifrele
    
    Args:
        message: Şifrelenecek mesaj (string)
        password: Şifreleme anahtarı (string)
    
    Returns:
        Base64 encoded şifreli mesaj (string)
    """
    # Password'u 8 byte'a tamamla (DES için gerekli)
    key = password[:8].ljust(8, '0').encode('utf-8')
    
    # DES cipher oluştur
    cipher = DES.new(key, DES.MODE_ECB)
    
    # Mesajı encode et ve pad ekle
    message_bytes = message.encode('utf-8')
    padded_message = pad(message_bytes, DES.block_size)
    
    # Şifrele
    encrypted = cipher.encrypt(padded_message)
    
    # Base64 encode et (network transfer için)
    encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')
    
    return encrypted_b64


def decrypt_message(encrypted_message, password):
    """
    Şifreli mesajı DES ile çöz
    
    Args:
        encrypted_message: Base64 encoded şifreli mesaj (string)
        password: Şifre çözme anahtarı (string)
    
    Returns:
        Çözülmüş mesaj (string)
    """
    # Password'u 8 byte'a tamamla
    key = password[:8].ljust(8, '0').encode('utf-8')
    
    # Base64 decode et
    encrypted_bytes = base64.b64decode(encrypted_message.encode('utf-8'))
    
    # DES cipher oluştur
    cipher = DES.new(key, DES.MODE_ECB)
    
    # Çöz
    decrypted_padded = cipher.decrypt(encrypted_bytes)
    
    # Pad'i kaldır
    decrypted = unpad(decrypted_padded, DES.block_size)
    
    # String'e çevir
    message = decrypted.decode('utf-8')
    
    return message

