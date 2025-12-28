CLIENT FONKSİYONLARI


Client tarafında register ve login işlemleri yapılacak.

Kullanıcı username password ve fotoğrafını verip register olacak.

Client tarafında bulunan LSB steganografi fonksiyonu passwordu fotoğraf içine gömecek.

Register çalıştığında parola gömülü fotoğraf ve kullanıcı adı ve normal fotoğraf server tarafına gönderilecek.

Client tarafında DES ile encrypt ve decrypt işlemleri yapılacak.

Gönderilen mesaj DES ile şifrelenerek servera gidecek.

Client tarafında serverdan gelen şifreli mesaj DES ile çözülecek ve kullanıcı mesajı görecek.  

Client tarafında kullanıcılar listelenecek.

Offline kullanıcılara da mesaj gönderilebilecek.


SERVER FONKSİYONLARI

Registerdan gelen bilgilerle kullanıcı kaydı yapılacak.

Fotoğraf içine gömülen password çıkarılacak ve kullanıcının adı ile eşleştirilecek.

Server tarafında da DES ile şifreleme ve çözme işlemleri yapılacak.

Gönderenin parolası ile şifrelenen mesajı çözecek alıcı clientın parolası ile şifreleyip alıcıya gönderecek. 
