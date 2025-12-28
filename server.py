"""
Secure Chat Server
Kullanıcı kayıt, login, mesaj yönlendirme işlemleri
"""
import socket
import threading
import json
import pickle
import os
from steganography import extract_password, load_image_to_array
from crypto import decrypt_message, encrypt_message


class ChatServer:
    def __init__(self, host='localhost', port=8888):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Kullanıcı veritabanı (username -> {password, photo_path, socket, online})
        self.users = {}
        # Bekleyen mesajlar (username -> [messages])
        self.pending_messages = {}
        
        # Veri klasörü
        self.data_dir = "server_data"
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
            os.makedirs(os.path.join(self.data_dir, "photos"))
            os.makedirs(os.path.join(self.data_dir, "embedded_photos"))
        
        # Kullanıcıları dosyadan yükle
        self.load_users()
    
    def start(self):
        """Server'ı başlat"""
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        print(f"Server {self.host}:{self.port} adresinde dinleniyor...")
        
        while True:
            client_socket, address = self.socket.accept()
            print(f"Yeni bağlantı: {address}")
            client_thread = threading.Thread(
                target=self.handle_client,
                args=(client_socket, address)
            )
            client_thread.daemon = True
            client_thread.start()
    
    def handle_client(self, client_socket, address):
        """Client bağlantısını yönet"""
        try:
            while True:
                # Mesaj tipini al
                msg_type = self.receive_data(client_socket)
                if not msg_type:
                    break
                
                msg_type = msg_type.decode('utf-8')
                
                if msg_type == "REGISTER":
                    self.handle_register(client_socket)
                elif msg_type == "LOGIN":
                    self.handle_login(client_socket)
                elif msg_type == "SEND_MESSAGE":
                    self.handle_send_message(client_socket)
                elif msg_type == "GET_USERS":
                    self.handle_get_users(client_socket)
                elif msg_type == "LOGOUT":
                    self.handle_logout(client_socket)
                    break
                    
        except Exception as e:
            print(f"Client hatası ({address}): {e}")
        finally:
            client_socket.close()
            # Kullanıcıyı offline yap
            for username, user_data in self.users.items():
                if user_data.get('socket') == client_socket:
                    user_data['online'] = False
                    user_data['socket'] = None
                    print(f"{username} bağlantısı kesildi")
                    break
    
    def receive_data(self, socket):
        """Socket'ten veri al"""
        try:
            length = int.from_bytes(socket.recv(4), 'big')
            data = b''
            while len(data) < length:
                chunk = socket.recv(length - len(data))
                if not chunk:
                    return None
                data += chunk
            return data
        except:
            return None
    
    def send_data(self, socket, data):
        """Socket'e veri gönder"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        length = len(data).to_bytes(4, 'big')
        socket.sendall(length + data)
    
    def load_users(self):
        """Kayıtlı kullanıcıları dosyadan yükle"""
        users_file = os.path.join(self.data_dir, "users.json")
        if os.path.exists(users_file):
            try:
                with open(users_file, 'r') as f:
                    users_data = json.load(f)
                    for username, user_info in users_data.items():
                        # Gömülü fotoğraftan password'u tekrar çıkar
                        embedded_photo_path = user_info.get('embedded_photo_path')
                        if embedded_photo_path and os.path.exists(embedded_photo_path):
                            try:
                                embedded_array = load_image_to_array(embedded_photo_path)
                                extracted_password = extract_password(embedded_array)
                                if extracted_password:
                                    self.users[username] = {
                                        'password': extracted_password,
                                        'photo_path': user_info.get('photo_path'),
                                        'embedded_photo_path': embedded_photo_path,
                                        'socket': None,
                                        'online': False
                                    }
                                    self.pending_messages[username] = []
                                    print(f"Kullanıcı yüklendi: {username}")
                            except Exception as e:
                                print(f"Kullanıcı yükleme hatası ({username}): {e}")
            except Exception as e:
                print(f"Users dosyası okuma hatası: {e}")
    
    def save_users(self):
        """Kullanıcıları dosyaya kaydet"""
        users_file = os.path.join(self.data_dir, "users.json")
        try:
            users_data = {}
            for username, user_info in self.users.items():
                users_data[username] = {
                    'photo_path': user_info.get('photo_path'),
                    'embedded_photo_path': user_info.get('embedded_photo_path')
                }
            with open(users_file, 'w') as f:
                json.dump(users_data, f, indent=2)
        except Exception as e:
            print(f"Users dosyası kaydetme hatası: {e}")
    
    def handle_register(self, client_socket):
        """Kullanıcı kaydı"""
        try:
            # Kullanıcı bilgilerini al
            username_data = self.receive_data(client_socket)
            if not username_data:
                self.send_data(client_socket, "ERROR: Kullanıcı adı alınamadı")
                return
            username = username_data.decode('utf-8')
            print(f"Kayıt işlemi başlatıldı: {username}")
            
            # Normal fotoğrafı al
            photo_data = self.receive_data(client_socket)
            if not photo_data:
                self.send_data(client_socket, "ERROR: Fotoğraf alınamadı")
                return
            photo_path = os.path.join(self.data_dir, "photos", f"{username}.png")
            with open(photo_path, 'wb') as f:
                f.write(photo_data)
            print(f"Fotoğraf kaydedildi: {photo_path}")
            
            # Gömülü fotoğrafı al
            embedded_photo_data = self.receive_data(client_socket)
            if not embedded_photo_data:
                self.send_data(client_socket, "ERROR: Gömülü fotoğraf alınamadı")
                return
            embedded_photo_path = os.path.join(self.data_dir, "embedded_photos", f"{username}_embedded.png")
            with open(embedded_photo_path, 'wb') as f:
                f.write(embedded_photo_data)
            print(f"Gömülü fotoğraf kaydedildi: {embedded_photo_path}")
            
            # Gömülü fotoğraftan password'u çıkar
            embedded_array = load_image_to_array(embedded_photo_path)
            extracted_password = extract_password(embedded_array)
            print(f"Çıkarılan password: [{extracted_password}] (uzunluk: {len(extracted_password)})")
            
            if not extracted_password:
                self.send_data(client_socket, "ERROR: Password çıkarılamadı")
                return
            
            # Kullanıcıyı kaydet
            self.users[username] = {
                'password': extracted_password,
                'photo_path': photo_path,
                'embedded_photo_path': embedded_photo_path,
                'socket': None,
                'online': False
            }
            
            # Bekleyen mesajlar listesi oluştur
            self.pending_messages[username] = []
            
            # Dosyaya kaydet
            self.save_users()
            
            print(f"Yeni kullanıcı kaydedildi: {username}, Password: {extracted_password}")
            self.send_data(client_socket, "SUCCESS: Kayıt başarılı")
            
        except Exception as e:
            import traceback
            print(f"Register hatası: {e}")
            print(traceback.format_exc())
            self.send_data(client_socket, f"ERROR: {str(e)}")
    
    def handle_login(self, client_socket):
        """Kullanıcı girişi"""
        try:
            username_data = self.receive_data(client_socket)
            if not username_data:
                self.send_data(client_socket, "ERROR: Kullanıcı adı alınamadı")
                return
            username = username_data.decode('utf-8')
            
            password_data = self.receive_data(client_socket)
            if not password_data:
                self.send_data(client_socket, "ERROR: Şifre alınamadı")
                return
            password = password_data.decode('utf-8')
            
            print(f"Login denemesi: {username}, Password: {password}")
            print(f"Mevcut kullanıcılar: {list(self.users.keys())}")
            
            if username not in self.users:
                # Kullanıcıyı tekrar yükle
                self.load_users()
                if username not in self.users:
                    self.send_data(client_socket, "ERROR: Kullanıcı bulunamadı")
                    print(f"Kullanıcı bulunamadı: {username}")
                    return
            
            stored_password = self.users[username]['password']
            print(f"Kayıtlı password: [{stored_password}], Gelen password: [{password}]")
            
            if stored_password != password:
                self.send_data(client_socket, "ERROR: Yanlış şifre")
                print(f"Şifre eşleşmedi: beklenen [{stored_password}], gelen [{password}]")
                return
            
            # Kullanıcıyı online yap
            self.users[username]['online'] = True
            self.users[username]['socket'] = client_socket
            
            print(f"{username} giriş yaptı")
            self.send_data(client_socket, "SUCCESS: Giriş başarılı")
            
            # Bekleyen mesajları gönder
            if username in self.pending_messages:
                for msg in self.pending_messages[username]:
                    self.send_message_to_user(username, msg['from'], msg['encrypted_message'])
                self.pending_messages[username] = []
            
        except Exception as e:
            print(f"Login hatası: {e}")
            self.send_data(client_socket, f"ERROR: {str(e)}")
    
    def handle_send_message(self, client_socket):
        """Mesaj gönderme"""
        try:
            # Gönderen kullanıcıyı bul
            sender = None
            for username, user_data in self.users.items():
                if user_data.get('socket') == client_socket:
                    sender = username
                    break
            
            if not sender:
                self.send_data(client_socket, "ERROR: Oturum açılmamış")
                return
            
            # Alıcı ve mesajı al
            receiver_data = self.receive_data(client_socket)
            if not receiver_data:
                self.send_data(client_socket, "ERROR: Alıcı bilgisi alınamadı")
                return
            receiver = receiver_data.decode('utf-8')
            
            encrypted_message_data = self.receive_data(client_socket)
            if not encrypted_message_data:
                self.send_data(client_socket, "ERROR: Mesaj alınamadı")
                return
            encrypted_message = encrypted_message_data.decode('utf-8')
            
            if receiver not in self.users:
                self.send_data(client_socket, "ERROR: Alıcı bulunamadı")
                return
            
            # Gönderenin password'u ile mesajı çöz
            sender_password = self.users[sender]['password']
            try:
                decrypted_message = decrypt_message(encrypted_message, sender_password)
            except:
                self.send_data(client_socket, "ERROR: Mesaj çözülemedi")
                return
            
            # Alıcının password'u ile mesajı şifrele
            receiver_password = self.users[receiver]['password']
            re_encrypted_message = encrypt_message(decrypted_message, receiver_password)
            
            # Mesajı gönder veya beklet
            try:
                if self.users[receiver]['online']:
                    send_success = self.send_message_to_user(receiver, sender, re_encrypted_message)
                    if send_success:
                        self.send_data(client_socket, "SUCCESS: Mesaj gönderildi")
                        print(f"{sender} -> {receiver}: Mesaj gönderildi")
                    else:
                        # Gönderilemediyse beklet
                        self.pending_messages[receiver].append({
                            'from': sender,
                            'encrypted_message': re_encrypted_message
                        })
                        self.send_data(client_socket, "SUCCESS: Mesaj kaydedildi (alıcı bağlantısı kesildi)")
                        print(f"{sender} -> {receiver}: Mesaj kaydedildi (alıcı bağlantısı kesildi)")
                else:
                    # Offline kullanıcı için mesajı beklet
                    self.pending_messages[receiver].append({
                        'from': sender,
                        'encrypted_message': re_encrypted_message
                    })
                    self.send_data(client_socket, "SUCCESS: Mesaj kaydedildi (kullanıcı offline)")
                    print(f"{sender} -> {receiver}: Mesaj kaydedildi (kullanıcı offline)")
            except Exception as e:
                print(f"Mesaj gönderme hatası: {e}")
                self.send_data(client_socket, f"ERROR: Mesaj gönderilemedi: {str(e)}")
            
        except Exception as e:
            print(f"Send message hatası: {e}")
            self.send_data(client_socket, f"ERROR: {str(e)}")
    
    def send_message_to_user(self, receiver, sender, encrypted_message):
        """Kullanıcıya mesaj gönder"""
        try:
            receiver_socket = self.users[receiver]['socket']
            if receiver_socket:
                try:
                    self.send_data(receiver_socket, "MESSAGE")
                    self.send_data(receiver_socket, sender)
                    self.send_data(receiver_socket, encrypted_message)
                    return True
                except Exception as e:
                    print(f"Socket gönderme hatası ({receiver}): {e}")
                    # Socket bağlantısı kesilmiş olabilir
                    self.users[receiver]['online'] = False
                    self.users[receiver]['socket'] = None
                    return False
            else:
                print(f"Kullanıcı {receiver} socket'i yok")
                return False
        except Exception as e:
            print(f"Mesaj gönderme hatası ({receiver}): {e}")
            return False
    
    def handle_get_users(self, client_socket):
        """Kullanıcı listesini gönder"""
        try:
            users_list = []
            for username, user_data in self.users.items():
                users_list.append({
                    'username': username,
                    'online': user_data['online']
                })
            
            users_json = json.dumps(users_list)
            self.send_data(client_socket, users_json)
            
        except Exception as e:
            print(f"Get users hatası: {e}")
            self.send_data(client_socket, "ERROR")
    
    def handle_logout(self, client_socket):
        """Kullanıcı çıkışı"""
        for username, user_data in self.users.items():
            if user_data.get('socket') == client_socket:
                user_data['online'] = False
                user_data['socket'] = None
                print(f"{username} çıkış yaptı")
                break
        
        # Socket'i kapat
        try:
            client_socket.close()
        except:
            pass


if __name__ == "__main__":
    server = ChatServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nServer kapatılıyor...")

