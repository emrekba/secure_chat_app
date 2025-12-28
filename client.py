"""
Secure Chat Client
Modern GUI arayüzlü client uygulaması
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import socket
import threading
import json
import os
from datetime import datetime
from steganography import embed_password, save_embedded_image, load_image_to_array
from crypto import encrypt_message, decrypt_message


class ChatWindow:
    """Her kullanıcı için ayrı mesaj penceresi"""
    def __init__(self, parent, client, receiver_username):
        self.parent = parent
        self.client = client
        self.receiver_username = receiver_username
        
        # Pencere oluştur
        self.window = tk.Toplevel(parent)
        self.window.title(f"Chat - {receiver_username}")
        self.window.geometry("600x500")
        
        # Mesaj geçmişi dosyası
        self.history_dir = "chat_history"
        if not os.path.exists(self.history_dir):
            os.makedirs(self.history_dir)
        self.history_file = os.path.join(self.history_dir, f"{client.username}_{receiver_username}.json")
        
        self.setup_ui()
        self.load_history()
    
    def setup_ui(self):
        """Pencere arayüzünü oluştur"""
        # Ana frame
        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Başlık
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(title_frame, text=f"💬 {self.receiver_username}", font=("Arial", 14, "bold")).pack(side=tk.LEFT)
        
        # Mesaj görüntüleme alanı
        messages_frame = ttk.Frame(main_frame)
        messages_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.messages_display = scrolledtext.ScrolledText(
            messages_frame, 
            width=60, 
            height=20, 
            state="disabled",
            wrap=tk.WORD,
            font=("Arial", 10)
        )
        self.messages_display.pack(fill=tk.BOTH, expand=True)
        
        # Mesaj gönderme alanı
        send_frame = ttk.Frame(main_frame)
        send_frame.pack(fill=tk.X)
        
        self.message_entry = ttk.Entry(send_frame, font=("Arial", 11))
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.message_entry.bind("<Return>", lambda e: self.send_message())
        
        send_btn = ttk.Button(send_frame, text="Gönder", command=self.send_message)
        send_btn.pack(side=tk.RIGHT)
        
        # Pencere kapatıldığında
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def send_message(self):
        """Mesaj gönder"""
        message = self.message_entry.get().strip()
        if not message:
            return
        
        if not self.client.username:
            messagebox.showerror("Hata", "Önce giriş yapın!")
            return
        
        try:
            # Mesajı DES ile şifrele
            encrypted_message = encrypt_message(message, self.client.password)
            
            # Server'a gönder
            self.client.send_data("SEND_MESSAGE")
            self.client.send_data(self.receiver_username)
            self.client.send_data(encrypted_message)
            
            # Yanıtı al (timeout ile)
            response_data = self.client.receive_data(timeout=10.0)
            if not response_data:
                messagebox.showerror("Hata", "Server'dan yanıt alınamadı. Mesaj gönderilemedi.")
                return
            response = response_data.decode('utf-8')
            
            if response.startswith("SUCCESS"):
                # Mesajı ekrana ekle (sadece başarılı olduğunda)
                self.add_message(self.client.username, message, is_sent=True)
                self.message_entry.delete(0, tk.END)
            else:
                messagebox.showerror("Hata", response)
                
        except Exception as e:
            messagebox.showerror("Hata", f"Mesaj gönderme hatası: {str(e)}")
    
    def add_message(self, sender, message, is_sent=False):
        """Mesaj ekranına mesaj ekle"""
        self.messages_display.config(state="normal")
        
        timestamp = datetime.now().strftime("%H:%M")
        
        if is_sent:
            # Gönderilen mesaj (sağda)
            self.messages_display.insert(tk.END, f"[{timestamp}] Sen: {message}\n", "sent")
            self.messages_display.tag_config("sent", foreground="blue", justify=tk.RIGHT)
        else:
            # Alınan mesaj (solda)
            self.messages_display.insert(tk.END, f"[{timestamp}] {sender}: {message}\n", "received")
            self.messages_display.tag_config("received", foreground="green", justify=tk.LEFT)
        
        self.messages_display.see(tk.END)
        self.messages_display.config(state="disabled")
        
        # Geçmişe kaydet
        self.save_message(sender, message, is_sent)
    
    def save_message(self, sender, message, is_sent):
        """Mesajı geçmişe kaydet"""
        try:
            # Mevcut geçmişi yükle
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    history = json.load(f)
            else:
                history = []
            
            # Yeni mesajı ekle
            history.append({
                'sender': sender,
                'message': message,
                'is_sent': is_sent,
                'timestamp': datetime.now().isoformat()
            })
            
            # Kaydet
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(history, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Geçmiş kaydetme hatası: {e}")
    
    def load_history(self):
        """Mesaj geçmişini yükle"""
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    history = json.load(f)
                
                for msg in history:
                    sender = msg['sender']
                    message = msg['message']
                    is_sent = msg.get('is_sent', False)
                    
                    # Timestamp'i parse et
                    try:
                        timestamp = datetime.fromisoformat(msg.get('timestamp', ''))
                        time_str = timestamp.strftime("%H:%M")
                    except:
                        time_str = "??:??"
                    
                    self.messages_display.config(state="normal")
                    if is_sent:
                        self.messages_display.insert(tk.END, f"[{time_str}] Sen: {message}\n", "sent")
                    else:
                        self.messages_display.insert(tk.END, f"[{time_str}] {sender}: {message}\n", "received")
                    self.messages_display.config(state="disabled")
                
                self.messages_display.see(tk.END)
        except Exception as e:
            print(f"Geçmiş yükleme hatası: {e}")
    
    def on_close(self):
        """Pencere kapatıldığında"""
        # Client'tan bu pencereyi kaldır
        if self.receiver_username in self.client.chat_windows:
            del self.client.chat_windows[self.receiver_username]
        self.window.destroy()


class ChatClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Güvenli Chat Uygulaması")
        self.root.geometry("400x600")
        
        self.socket = None
        self.username = None
        self.password = None
        self.connected = False
        
        # Açık chat pencereleri
        self.chat_windows = {}
        
        # Socket işlemleri için lock
        self.socket_lock = threading.Lock()
        
        # Server bilgileri
        self.server_host = "localhost"
        self.server_port = 8888
        
        self.setup_ui()
        self.start_message_listener()
        
        # Pencere kapatıldığında temizlik yap
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def setup_ui(self):
        """Arayüzü oluştur"""
        # Ana frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Bağlantı frame
        connection_frame = ttk.LabelFrame(main_frame, text="Bağlantı", padding="5")
        connection_frame.pack(fill=tk.X, pady=(0, 10))
        
        server_frame = ttk.Frame(connection_frame)
        server_frame.pack(fill=tk.X)
        
        ttk.Label(server_frame, text="Server:").pack(side=tk.LEFT, padx=5)
        self.server_entry = ttk.Entry(server_frame, width=15)
        self.server_entry.insert(0, f"{self.server_host}:{self.server_port}")
        self.server_entry.pack(side=tk.LEFT, padx=5)
        
        self.connect_btn = ttk.Button(server_frame, text="Bağlan", command=self.connect_to_server)
        self.connect_btn.pack(side=tk.LEFT, padx=5)
        
        self.status_label = ttk.Label(connection_frame, text="Bağlantı yok", foreground="red")
        self.status_label.pack(pady=5)
        
        # Giriş/Kayıt notebook
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Login tab
        login_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(login_frame, text="Giriş Yap")
        self.setup_login_tab(login_frame)
        
        # Register tab
        register_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(register_frame, text="Kayıt Ol")
        self.setup_register_tab(register_frame)
        
        # Chat tab (başlangıçta gizli)
        self.chat_frame = ttk.Frame(self.notebook, padding="10")
        self.setup_chat_tab(self.chat_frame)
    
    def setup_login_tab(self, parent):
        """Giriş sekmesi"""
        ttk.Label(parent, text="Kullanıcı Adı:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.login_username = ttk.Entry(parent, width=30)
        self.login_username.grid(row=0, column=1, pady=5, padx=5)
        
        ttk.Label(parent, text="Şifre:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.login_password = ttk.Entry(parent, width=30, show="*")
        self.login_password.grid(row=1, column=1, pady=5, padx=5)
        
        ttk.Button(parent, text="Giriş Yap", command=self.login).grid(row=2, column=0, columnspan=2, pady=10)
    
    def setup_register_tab(self, parent):
        """Kayıt sekmesi"""
        ttk.Label(parent, text="Kullanıcı Adı:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.register_username = ttk.Entry(parent, width=30)
        self.register_username.grid(row=0, column=1, pady=5, padx=5)
        
        ttk.Label(parent, text="Şifre:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.register_password = ttk.Entry(parent, width=30, show="*")
        self.register_password.grid(row=1, column=1, pady=5, padx=5)
        
        ttk.Label(parent, text="Fotoğraf:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.photo_path = tk.StringVar()
        ttk.Entry(parent, textvariable=self.photo_path, width=25, state="readonly").grid(row=2, column=1, pady=5, padx=5, sticky=(tk.W, tk.E))
        ttk.Button(parent, text="Seç", command=self.select_photo).grid(row=2, column=2, padx=5)
        
        ttk.Button(parent, text="Kayıt Ol", command=self.register).grid(row=3, column=0, columnspan=3, pady=10)
    
    def setup_chat_tab(self, parent):
        """Chat sekmesi - Kullanıcı listesi"""
        # Kullanıcı listesi
        users_frame = ttk.LabelFrame(parent, text="Kullanıcılar", padding="5")
        users_frame.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbar ile listbox
        listbox_frame = ttk.Frame(users_frame)
        listbox_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(listbox_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.users_listbox = tk.Listbox(
            listbox_frame, 
            width=30, 
            height=20,
            yscrollcommand=scrollbar.set,
            font=("Arial", 11)
        )
        self.users_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.users_listbox.yview)
        
        # Çift tıklama ile mesaj penceresi aç
        self.users_listbox.bind("<Double-Button-1>", self.on_user_double_click)
        
        # Yenile butonu
        ttk.Button(users_frame, text="🔄 Yenile", command=self.refresh_users).pack(pady=5)
    
    def on_user_double_click(self, event):
        """Kullanıcıya çift tıklandığında mesaj penceresi aç"""
        selection = self.users_listbox.curselection()
        if not selection:
            return
        
        selected_text = self.users_listbox.get(selection[0])
        # "🟢 username" veya "🔴 username" formatından username'i çıkar
        username = selected_text.split(" ", 1)[1] if " " in selected_text else selected_text
        
        # Kendi kullanıcı adını atla
        if username == self.username:
            return
        
        # Eğer pencere zaten açıksa, öne getir
        if username in self.chat_windows:
            self.chat_windows[username].window.lift()
            self.chat_windows[username].window.focus()
        else:
            # Yeni pencere aç
            chat_window = ChatWindow(self.root, self, username)
            self.chat_windows[username] = chat_window
    
    def select_photo(self):
        """Fotoğraf seç"""
        filename = filedialog.askopenfilename(
            title="Fotoğraf Seç",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp")]
        )
        if filename:
            self.photo_path.set(filename)
    
    def connect_to_server(self):
        """Server'a bağlan"""
        try:
            server_info = self.server_entry.get().split(":")
            host = server_info[0]
            port = int(server_info[1])
            
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((host, port))
            self.connected = True
            self.status_label.config(text="Bağlı", foreground="green")
            messagebox.showinfo("Başarılı", "Server'a bağlanıldı!")
        except Exception as e:
            messagebox.showerror("Hata", f"Bağlantı hatası: {str(e)}")
            self.status_label.config(text="Bağlantı yok", foreground="red")
    
    def send_data(self, data):
        """Server'a veri gönder (thread-safe)"""
        with self.socket_lock:
            if isinstance(data, str):
                data = data.encode('utf-8')
            length = len(data).to_bytes(4, 'big')
            self.socket.sendall(length + data)
    
    def receive_data(self, timeout=5.0):
        """Server'dan veri al (thread-safe)"""
        with self.socket_lock:
            try:
                # Timeout ayarla
                old_timeout = self.socket.gettimeout()
                self.socket.settimeout(timeout)
                
                length_bytes = self.socket.recv(4)
                if not length_bytes or len(length_bytes) < 4:
                    self.socket.settimeout(old_timeout)
                    return None
                
                length = int.from_bytes(length_bytes, 'big')
                data = b''
                while len(data) < length:
                    chunk = self.socket.recv(length - len(data))
                    if not chunk:
                        self.socket.settimeout(old_timeout)
                        return None
                    data += chunk
                
                # Timeout'u geri al
                self.socket.settimeout(old_timeout)
                return data
            except socket.timeout:
                print("Socket timeout: Server'dan yanıt alınamadı")
                return None
            except Exception as e:
                print(f"receive_data hatası: {e}")
                return None
    
    def register(self):
        """Kullanıcı kaydı"""
        if not self.connected:
            messagebox.showerror("Hata", "Önce server'a bağlanın!")
            return
        
        username = self.register_username.get().strip()
        password = self.register_password.get()
        photo_file = self.photo_path.get()
        
        if not all([username, password, photo_file]):
            messagebox.showerror("Hata", "Tüm alanları doldurun!")
            return
        
        # Username'deki boşlukları temizle
        username = username.replace(" ", "_")
        
        try:
            # LSB steganografi ile password'u fotoğrafa göm
            embedded_array = embed_password(photo_file, password)
            
            # Geçici dosyalara kaydet
            temp_dir = "temp"
            if not os.path.exists(temp_dir):
                os.makedirs(temp_dir)
            
            embedded_photo_path = os.path.join(temp_dir, f"{username}_embedded.png")
            save_embedded_image(embedded_array, embedded_photo_path)
            
            # Server'a gönder
            self.send_data("REGISTER")
            self.send_data(username)
            
            # Normal fotoğrafı gönder
            with open(photo_file, 'rb') as f:
                photo_data = f.read()
            self.send_data(photo_data)
            
            # Gömülü fotoğrafı gönder
            with open(embedded_photo_path, 'rb') as f:
                embedded_data = f.read()
            self.send_data(embedded_data)
            
            # Yanıtı al
            response_data = self.receive_data()
            if not response_data:
                messagebox.showerror("Hata", "Server'dan yanıt alınamadı")
                return
            response = response_data.decode('utf-8')
            
            if response.startswith("SUCCESS"):
                messagebox.showinfo("Başarılı", "Kayıt başarılı! Giriş yapabilirsiniz.")
                self.register_username.delete(0, tk.END)
                self.register_password.delete(0, tk.END)
                self.photo_path.set("")
            else:
                messagebox.showerror("Hata", response)
            
            # Geçici dosyayı sil
            if os.path.exists(embedded_photo_path):
                os.remove(embedded_photo_path)
                
        except Exception as e:
            messagebox.showerror("Hata", f"Kayıt hatası: {str(e)}")
    
    def login(self):
        """Kullanıcı girişi"""
        if not self.connected:
            messagebox.showerror("Hata", "Önce server'a bağlanın!")
            return
        
        username = self.login_username.get().strip()
        password = self.login_password.get()
        
        if not username or not password:
            messagebox.showerror("Hata", "Kullanıcı adı ve şifre girin!")
            return
        
        # Username'deki boşlukları temizle
        username = username.replace(" ", "_")
        
        try:
            self.send_data("LOGIN")
            self.send_data(username)
            self.send_data(password)
            
            response_data = self.receive_data()
            if not response_data:
                messagebox.showerror("Hata", "Server'dan yanıt alınamadı")
                return
            response = response_data.decode('utf-8')
            
            if response.startswith("SUCCESS"):
                self.username = username
                self.password = password
                messagebox.showinfo("Başarılı", "Giriş başarılı!")
                self.notebook.add(self.chat_frame, text="Chat")
                self.notebook.select(2)
                self.refresh_users()
            else:
                messagebox.showerror("Hata", response)
                
        except Exception as e:
            messagebox.showerror("Hata", f"Giriş hatası: {str(e)}")
    
    def refresh_users(self):
        """Kullanıcı listesini yenile"""
        if not self.username:
            return
        
        try:
            self.send_data("GET_USERS")
            users_data = self.receive_data()
            if not users_data:
                print("Kullanıcı listesi alınamadı")
                return
            users_json = users_data.decode('utf-8')
            users = json.loads(users_json)
            
            self.users_listbox.delete(0, tk.END)
            for user in users:
                # Kendi kullanıcı adını atla
                if user['username'] == self.username:
                    continue
                
                status = "🟢" if user['online'] else "🔴"
                self.users_listbox.insert(tk.END, f"{status} {user['username']}")
                
        except Exception as e:
            print(f"Kullanıcı listesi hatası: {e}")
    
    def start_message_listener(self):
        """Mesaj dinleyici thread'i başlat"""
        def listener():
            while True:
                if self.socket and self.username and self.connected:
                    try:
                        # Non-blocking check için socket timeout ayarla
                        if self.socket:
                            with self.socket_lock:
                                try:
                                    # Listener için kısa timeout (1 saniye)
                                    old_timeout = self.socket.gettimeout()
                                    self.socket.settimeout(1.0)
                                    
                                    try:
                                        length_bytes = self.socket.recv(4)
                                        if not length_bytes or len(length_bytes) < 4:
                                            self.socket.settimeout(old_timeout)
                                            continue
                                        
                                        length = int.from_bytes(length_bytes, 'big')
                                        msg_type = b''
                                        while len(msg_type) < length:
                                            chunk = self.socket.recv(length - len(msg_type))
                                            if not chunk:
                                                self.socket.settimeout(old_timeout)
                                                break
                                            msg_type += chunk
                                        
                                        self.socket.settimeout(old_timeout)
                                        
                                        if len(msg_type) == length:
                                            msg_type_str = msg_type.decode('utf-8')
                                            if msg_type_str == "MESSAGE":
                                                # Lock içinde kalmadan devam et - receive_data zaten lock kullanıyor
                                                sender_data = self.receive_data(timeout=2.0)
                                                if not sender_data:
                                                    continue
                                                sender = sender_data.decode('utf-8')
                                                
                                                encrypted_message_data = self.receive_data(timeout=2.0)
                                                if not encrypted_message_data:
                                                    continue
                                                encrypted_message = encrypted_message_data.decode('utf-8')
                                                
                                                # Mesajı çöz
                                                try:
                                                    decrypted_message = decrypt_message(encrypted_message, self.password)
                                                    
                                                    # İlgili chat penceresine ekle (closure sorununu önlemek için)
                                                    def add_message(s=sender, m=decrypted_message):
                                                        self.handle_received_message(s, m)
                                                    self.root.after(0, add_message)
                                                except Exception as e:
                                                    print(f"Mesaj çözme hatası: {e}")
                                    except socket.timeout:
                                        pass
                                    except Exception as e:
                                        if self.socket and self.connected:
                                            print(f"Listener hatası: {e}")
                                except Exception as e:
                                    if self.socket and self.connected:
                                        print(f"Listener genel hatası: {e}")
                    except Exception as e:
                        if self.socket and self.connected:
                            print(f"Listener genel hatası: {e}")
                else:
                    import time
                    time.sleep(0.5)
        
        listener_thread = threading.Thread(target=listener, daemon=True)
        listener_thread.start()
    
    def handle_received_message(self, sender, message):
        """Gelen mesajı işle"""
        # Eğer bu kullanıcı için pencere açıksa, oraya ekle
        if sender in self.chat_windows:
            self.chat_windows[sender].add_message(sender, message, is_sent=False)
        else:
            # Pencere açık değilse, otomatik aç
            chat_window = ChatWindow(self.root, self, sender)
            self.chat_windows[sender] = chat_window
            chat_window.add_message(sender, message, is_sent=False)
    
    def on_closing(self):
        """Pencere kapatıldığında temizlik yap"""
        try:
            # Bağlantı durumunu güncelle (listener thread'i durdurmak için)
            self.connected = False
            
            # Tüm açık chat pencerelerini kapat
            for username, chat_window in list(self.chat_windows.items()):
                try:
                    chat_window.window.destroy()
                except:
                    pass
            
            # Server'a logout mesajı gönder
            if self.socket and self.username:
                try:
                    # Socket hala açıksa logout gönder
                    if hasattr(self.socket, 'fileno'):
                        try:
                            with self.socket_lock:
                                if self.socket:
                                    self.send_data("LOGOUT")
                            print("Logout mesajı gönderildi")
                        except Exception as e:
                            print(f"Logout gönderme hatası: {e}")
                except:
                    pass
            
            # Socket'i kapat
            if self.socket:
                try:
                    self.socket.close()
                    print("Socket kapatıldı")
                except:
                    pass
            
        except Exception as e:
            print(f"Kapatma hatası: {e}")
        finally:
            # Pencereyi kapat
            self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClient(root)
    root.mainloop()
