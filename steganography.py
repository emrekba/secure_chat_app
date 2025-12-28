"""
LSB (Least Significant Bit) Steganography Module
Password'u fotoğraf içine gömme ve çıkarma işlemleri
"""
import numpy as np
from PIL import Image


def embed_password(image_path, password):
    """
    Password'u fotoğrafın LSB'lerine göm
    
    Args:
        image_path: Kaynak fotoğraf yolu
        password: Gömülecek password
    
    Returns:
        Gömülü fotoğrafın numpy array'i
    """
    # Fotoğrafı yükle ve RGB'ye çevir
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    img_array = np.array(img)
    
    # Password'u binary string'e çevir
    password_binary = ''.join(format(ord(char), '08b') for char in password)
    password_length = len(password_binary)
    
    # Password uzunluğunu 32 bit ile başa ekle
    length_binary = format(password_length, '032b')
    full_message = length_binary + password_binary
    
    # Fotoğrafın boyutunu kontrol et
    total_pixels = img_array.size
    if len(full_message) > total_pixels:
        raise ValueError("Fotoğraf password için yeterince büyük değil!")
    
    # LSB'leri değiştir
    flat_array = img_array.flatten()
    message_index = 0
    
    for i in range(len(flat_array)):
        if message_index < len(full_message):
            # LSB'yi değiştir
            flat_array[i] = (flat_array[i] & 0xFE) | int(full_message[message_index])
            message_index += 1
        else:
            break
    
    # Array'i orijinal şekline geri döndür
    embedded_array = flat_array.reshape(img_array.shape)
    
    return embedded_array


def extract_password(image_array):
    """
    Fotoğrafın LSB'lerinden password'u çıkar
    
    Args:
        image_array: Password gömülü fotoğraf array'i
    
    Returns:
        Çıkarılan password string'i
    """
    flat_array = image_array.flatten()
    
    # İlk 32 bit'ten password uzunluğunu oku
    length_binary = ''
    for i in range(32):
        if i < len(flat_array):
            length_binary += str(flat_array[i] & 1)
        else:
            return ""
    
    password_length = int(length_binary, 2)
    
    # Password'u oku
    password_binary = ''
    for i in range(32, 32 + password_length):
        if i < len(flat_array):
            password_binary += str(flat_array[i] & 1)
        else:
            return ""
    
    # Binary'den string'e çevir
    password = ''
    for i in range(0, len(password_binary), 8):
        if i + 8 <= len(password_binary):
            char_binary = password_binary[i:i+8]
            password += chr(int(char_binary, 2))
    
    return password


def save_embedded_image(image_array, output_path):
    """
    Gömülü fotoğrafı kaydet
    
    Args:
        image_array: Gömülü fotoğraf array'i
        output_path: Kayıt yolu
    """
    img = Image.fromarray(image_array.astype(np.uint8), mode='RGB')
    img.save(output_path)


def load_image_to_array(image_path):
    """
    Fotoğrafı numpy array'e yükle
    
    Args:
        image_path: Fotoğraf yolu
    
    Returns:
        Fotoğrafın numpy array'i
    """
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    return np.array(img)

