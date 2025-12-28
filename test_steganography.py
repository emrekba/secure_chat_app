#!/usr/bin/env python3
"""
Steganografi Test Scripti
Şifrenin fotoğrafa gömülü olup olmadığını kontrol eder
"""
import sys
import os
from steganography import embed_password, extract_password, load_image_to_array, save_embedded_image

def test_password_embedding(image_path, password):
    """Password'u fotoğrafa göm ve çıkar, sonucu kontrol et"""
    print("=" * 60)
    print("STEGANOGRAFİ TESTİ")
    print("=" * 60)
    print(f"Fotoğraf: {image_path}")
    print(f"Gömülecek şifre: {password}")
    print()
    
    try:
        # 1. Password'u fotoğrafa göm
        print("1. Password fotoğrafa gömülüyor...")
        embedded_array = embed_password(image_path, password)
        print("   ✓ Password gömüldü")
        
        # 2. Gömülü fotoğrafı geçici olarak kaydet
        temp_path = "test_embedded.png"
        save_embedded_image(embedded_array, temp_path)
        print(f"   ✓ Gömülü fotoğraf kaydedildi: {temp_path}")
        
        # 3. Gömülü fotoğraftan password'u çıkar
        print("\n2. Gömülü fotoğraftan password çıkarılıyor...")
        extracted_array = load_image_to_array(temp_path)
        extracted_password = extract_password(extracted_array)
        
        # 4. Sonuçları karşılaştır
        print("\n3. Sonuçlar:")
        print(f"   Orijinal şifre:     [{password}]")
        print(f"   Çıkarılan şifre:    [{extracted_password}]")
        print(f"   Şifre uzunluğu:     {len(password)} karakter")
        print(f"   Çıkarılan uzunluk:  {len(extracted_password)} karakter")
        
        if password == extracted_password:
            print("\n   ✓✓✓ BAŞARILI: Şifre doğru çıkarıldı! ✓✓✓")
            return True
        else:
            print("\n   ✗✗✗ HATA: Şifre eşleşmiyor! ✗✗✗")
            return False
            
    except Exception as e:
        print(f"\n   ✗ HATA: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Geçici dosyayı temizle
        if os.path.exists(temp_path):
            os.remove(temp_path)
            print(f"\n   ✓ Geçici dosya temizlendi: {temp_path}")

def test_server_embedded_image(embedded_image_path):
    """Server'da kaydedilen gömülü fotoğraftan password çıkar"""
    print("=" * 60)
    print("SERVER'DAKİ GÖMÜLÜ FOTOĞRAFTAN PASSWORD ÇIKARMA")
    print("=" * 60)
    print(f"Fotoğraf: {embedded_image_path}")
    print()
    
    if not os.path.exists(embedded_image_path):
        print(f"✗ HATA: Dosya bulunamadı: {embedded_image_path}")
        return None
    
    try:
        print("Password çıkarılıyor...")
        embedded_array = load_image_to_array(embedded_image_path)
        extracted_password = extract_password(embedded_array)
        
        print(f"\nÇıkarılan password: [{extracted_password}]")
        print(f"Password uzunluğu: {len(extracted_password)} karakter")
        
        if extracted_password:
            print("\n✓✓✓ BAŞARILI: Password çıkarıldı! ✓✓✓")
        else:
            print("\n✗✗✗ HATA: Password çıkarılamadı! ✗✗✗")
        
        return extracted_password
        
    except Exception as e:
        print(f"\n✗ HATA: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("Kullanım:")
        print("  1. Yeni fotoğraf testi:")
        print("     python3 test_steganography.py <fotoğraf_yolu> <şifre>")
        print()
        print("  2. Server'daki gömülü fotoğrafı test et:")
        print("     python3 test_steganography.py --server <kullanıcı_adı>")
        print()
        print("Örnek:")
        print("  python3 test_steganography.py photo.jpg mypassword123")
        print("  python3 test_steganography.py --server emre")
        sys.exit(1)
    
    if sys.argv[1] == "--server":
        # Server'daki gömülü fotoğrafı test et
        if len(sys.argv) < 3:
            print("Kullanıcı adı gerekli!")
            sys.exit(1)
        
        username = sys.argv[2]
        embedded_path = f"server_data/embedded_photos/{username}_embedded.png"
        test_server_embedded_image(embedded_path)
        
    else:
        # Yeni fotoğraf testi
        if len(sys.argv) < 3:
            print("Fotoğraf yolu ve şifre gerekli!")
            sys.exit(1)
        
        image_path = sys.argv[1]
        password = sys.argv[2]
        
        if not os.path.exists(image_path):
            print(f"✗ HATA: Fotoğraf bulunamadı: {image_path}")
            sys.exit(1)
        
        success = test_password_embedding(image_path, password)
        sys.exit(0 if success else 1)

