 Secure Messaging App (Steganography & DES)
 Client-Server mimarisinde çalışan, LSB steganografi ve DES şifreleme algoritmaları kullanarak yüksek güvenlikli iletişim sağlayan mesajlaşma uygulaması.

 Client

-Steganografik Kayıt: Kullanıcı parolasını LSB algoritmasıyla profil fotoğrafına gömer ve server tarafına iletir.

-Client Taraflı Şifreleme: Mesajlar doğrudan client üzerinde DES algoritması ve kullanıcı parolası ile şifrelenir/çözülür.

-Asenkron İletişim: Çevrimdışı kullanıcılara mesaj gönderme ve durum takibi desteği.

 Server

-Gizli Veri Çıkarımı: Kayıt olan kullanıcının fotoğrafından parolayı steganografik olarak çıkarır ve doğrular.

-Güvenli Mesaj Yönlendirme: Gelen mesajı göndericinin parolasıyla çözer, alıcıya iletmeden önce alıcının parolasıyla tekrar şifreler. Mesajlar ağda açık halde bulunmaz.
