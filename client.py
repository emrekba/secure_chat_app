"""
Secure Chat Client
Simplified Single-Window Implementation
"""
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import socket
import threading
import json
import queue
import time
import os
from steganography import embed_password, save_embedded_image
from crypto import encrypt_message, decrypt_message

class ChatClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat")
        self.root.geometry("800x600")
        
        # State
        self.socket = None
        self.username = None
        self.password = None
        self.connected = False
        self.msg_queue = queue.Queue()
        self.selected_user = None
        self.chat_history = {} # {username: ["msg1", "msg2", ...]}
        
        self.setup_ui()
        self.root.after(100, self.process_queue)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def setup_ui(self):
        # 1. Connection Bar (Top)
        conn_frame = ttk.Frame(self.root, padding=5)
        conn_frame.pack(fill=tk.X)
        
        ttk.Label(conn_frame, text="Server:").pack(side=tk.LEFT)
        self.server_entry = ttk.Entry(conn_frame, width=20)
        self.server_entry.insert(0, "localhost:8888")
        self.server_entry.pack(side=tk.LEFT, padx=5)
        
        self.connect_btn = ttk.Button(conn_frame, text="Connect", command=self.connect_server)
        self.connect_btn.pack(side=tk.LEFT)
        
        self.status_lbl = ttk.Label(conn_frame, text="Disconnected", foreground="red")
        self.status_lbl.pack(side=tk.LEFT, padx=10)

        # 2. Main Area (Split: Login/Register VS Chat)
        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # We use a frame switching mechanism
        self.auth_frame = ttk.Frame(self.main_container)
        self.chat_frame = ttk.Frame(self.main_container)
        
        self.setup_auth_ui()
        self.setup_chat_ui()
        
        self.show_auth()

    def setup_auth_ui(self):
        # Notebook for Login / Register
        nb = ttk.Notebook(self.auth_frame)
        nb.pack(expand=True, fill=tk.BOTH)
        
        # Login
        f_login = ttk.Frame(nb, padding=20)
        nb.add(f_login, text="Login")
        
        ttk.Label(f_login, text="Username:").pack(pady=5)
        self.login_user = ttk.Entry(f_login)
        self.login_user.pack(pady=5)
        
        ttk.Label(f_login, text="Password:").pack(pady=5)
        self.login_pass = ttk.Entry(f_login, show="*")
        self.login_pass.pack(pady=5)
        
        ttk.Button(f_login, text="Login", command=self.login).pack(pady=20)
        
        # Register
        f_reg = ttk.Frame(nb, padding=20)
        nb.add(f_reg, text="Register")
        
        ttk.Label(f_reg, text="Username:").pack(pady=5)
        self.reg_user = ttk.Entry(f_reg)
        self.reg_user.pack(pady=5)
        
        ttk.Label(f_reg, text="Password:").pack(pady=5)
        self.reg_pass = ttk.Entry(f_reg, show="*")
        self.reg_pass.pack(pady=5)
        
        ttk.Label(f_reg, text="Security Photo:").pack(pady=5)
        self.photo_path_var = tk.StringVar()
        ttk.Entry(f_reg, textvariable=self.photo_path_var, state='readonly').pack(pady=5)
        ttk.Button(f_reg, text="Choose Photo", command=self.choose_photo).pack(pady=5)
        
        ttk.Button(f_reg, text="Register", command=self.register).pack(pady=20)

    def setup_chat_ui(self):
        # Paned Window: Users (Left) | Chat (Right)
        paned = ttk.PanedWindow(self.chat_frame, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)
        
        # Users List
        f_users = ttk.LabelFrame(paned, text="Users", padding=5)
        paned.add(f_users, weight=1)
        
        self.user_list = tk.Listbox(f_users)
        self.user_list.pack(fill=tk.BOTH, expand=True)
        self.user_list.bind('<<ListboxSelect>>', self.on_user_select)
        
        ttk.Button(f_users, text="Refresh", command=self.refresh_users).pack(fill=tk.X, pady=5)
        
        # Chat Area
        f_chat = ttk.LabelFrame(paned, text="Chat", padding=5)
        paned.add(f_chat, weight=3)
        
        self.chat_display = scrolledtext.ScrolledText(f_chat, state='disabled')
        self.chat_display.pack(fill=tk.BOTH, expand=True)
        
        f_input = ttk.Frame(f_chat)
        f_input.pack(fill=tk.X, pady=5)
        
        self.msg_entry = ttk.Entry(f_input)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.msg_entry.bind('<Return>', lambda e: self.send_message())
        
        ttk.Button(f_input, text="Send", command=self.send_message).pack(side=tk.LEFT, padx=5)

    def show_auth(self):
        self.chat_frame.pack_forget()
        self.auth_frame.pack(fill=tk.BOTH, expand=True)

    def show_chat(self):
        self.auth_frame.pack_forget()
        self.chat_frame.pack(fill=tk.BOTH, expand=True)

    def connect_server(self):
        if self.connected: return
        
        addr = self.server_entry.get().split(':')
        host = addr[0]
        port = int(addr[1]) if len(addr) > 1 else 8888
        
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((host, port))
            self.connected = True
            
            # Start listener thread
            threading.Thread(target=self.network_listener, daemon=True).start()
            
            self.status_lbl.config(text="Connected", foreground="green")
            self.connect_btn.config(state='disabled')
            
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))

    def network_listener(self):
        while self.connected:
            try:
                # Read length
                length_bytes = self.socket.recv(4)
                if not length_bytes: break
                length = int.from_bytes(length_bytes, 'big')
                
                # Read data
                data = b''
                while len(data) < length:
                    chunk = self.socket.recv(length - len(data))
                    if not chunk: break
                    data += chunk
                
                if not data: break
                
                # Parse JSON
                msg = json.loads(data.decode('utf-8'))
                self.msg_queue.put(msg)
                
            except Exception as e:
                print(f"Network error: {e}")
                self.msg_queue.put({'type': 'DISCONNECT', 'reason': str(e)})
                break
        
        self.connected = False
        self.msg_queue.put({'type': 'DISCONNECT', 'reason': "Connection closed"})

    def send_request(self, data):
        if not self.connected:
            messagebox.showerror("Error", "Not connected")
            return
        try:
            json_str = json.dumps(data)
            bytes_data = json_str.encode('utf-8')
            length = len(bytes_data).to_bytes(4, 'big')
            self.socket.sendall(length + bytes_data)
        except Exception as e:
            messagebox.showerror("Error", f"Send error: {e}")
            self.connected = False

    def process_queue(self):
        try:
            while True:
                msg = self.msg_queue.get_nowait()
                self.handle_message(msg)
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.process_queue)

    def handle_message(self, msg):
        status = msg.get('status')
        m_type = msg.get('type')
        
        if m_type == 'DISCONNECT':
            self.status_lbl.config(text="Disconnected", foreground="red")
            self.connect_btn.config(state='normal')
            self.show_auth()
            messagebox.showinfo("Disconnected", msg.get('reason'))
            
        elif m_type == 'USER_LIST':
            self.update_user_list(msg.get('users'))
            
        elif m_type == 'MESSAGE':
            sender = msg.get('sender')
            enc_text = msg.get('message')
            timestamp = msg.get('timestamp')
            
            # Decrypt
            try:
                dec_text = decrypt_message(enc_text, self.password)
                self.add_chat_history(sender, f"[{timestamp}] {sender}: {dec_text}", False)
            except Exception as e:
                self.add_chat_history(sender, f"[{timestamp}] {sender}: [Decryption Error]", False)
            
            if sender == self.selected_user:
                self.refresh_chat_display()

        # Handle Responses to our actions
        elif status == 'success':
            print(f"Success: {msg.get('message')}")
            # If login success
            if msg.get('message') == 'Logged in':
                self.show_chat()
                self.refresh_users()
            elif msg.get('message') == 'Registered successfully':
                messagebox.showinfo("Success", "Registered! Please login.")
        elif status == 'error':
            messagebox.showerror("Server Error", msg.get('message'))

    def choose_photo(self):
        f = filedialog.askopenfilename(filetypes=[("Images", "*.png;*.jpg;*.jpeg")])
        if f: self.photo_path_var.set(f)

    def register(self):
        u = self.reg_user.get()
        p = self.reg_pass.get()
        photo = self.photo_path_var.get()
        
        if not all([u, p, photo]):
            messagebox.showwarning("Warning", "All fields required")
            return
            
        # 1. Embed password in photo
        try:
            emb_arr = embed_password(photo, p)
            temp_path = "temp_embedded.png"
            save_embedded_image(emb_arr, temp_path)
            
            with open(photo, 'rb') as f: photo_data = f.read().hex()
            with open(temp_path, 'rb') as f: emb_data = f.read().hex()
            
            if os.path.exists(temp_path): os.remove(temp_path)
            
            self.send_request({
                'command': 'REGISTER',
                'username': u,
                'photo_data': photo_data,
                'embedded_data': emb_data
            })
        except Exception as e:
            messagebox.showerror("Error", f"Processing error: {e}")

    def login(self):
        u = self.login_user.get()
        p = self.login_pass.get()
        if not u or not p: return
        self.username = u
        self.password = p
        self.send_request({'command': 'LOGIN', 'username': u, 'password': p})

    def refresh_users(self):
        self.send_request({'command': 'GET_USERS'})

    def update_user_list(self, users):
        self.user_list.delete(0, tk.END)
        for u in users:
            name = u['username']
            if name == self.username: continue
            status = "🟢" if u['online'] else "🔴"
            self.user_list.insert(tk.END, f"{status} {name}")

    def on_user_select(self, event):
        sel = self.user_list.curselection()
        if not sel: return
        
        text = self.user_list.get(sel[0])
        username = text.split(" ")[1]
        self.selected_user = username
        self.refresh_chat_display()

    def refresh_chat_display(self):
        self.chat_display.config(state='normal')
        self.chat_display.delete(1.0, tk.END)
        
        msgs = self.chat_history.get(self.selected_user, [])
        for m in msgs:
            self.chat_display.insert(tk.END, m + "\n")
            
        self.chat_display.see(tk.END)
        self.chat_display.config(state='disabled')

    def add_chat_history(self, other_user, text, is_self):
        if other_user not in self.chat_history:
            self.chat_history[other_user] = []
        self.chat_history[other_user].append(text)

    def send_message(self):
        if not self.selected_user: return
        text = self.msg_entry.get().strip()
        if not text: return
        
        try:
            # Encrypt
            enc_text = encrypt_message(text, self.password)
            
            self.send_request({
                'command': 'SEND_MESSAGE',
                'target': self.selected_user,
                'message': enc_text
            })
            
            # Add to UI immediately
            timestamp = time.strftime("%H:%M")
            self.add_chat_history(self.selected_user, f"[{timestamp}] me: {text}", True)
            self.refresh_chat_display()
            self.msg_entry.delete(0, tk.END)
            
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def on_close(self):
        if self.connected:
            try:
                self.send_request({'command': 'LOGOUT'})
            except: pass
        self.connected = False
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClient(root)
    root.mainloop()
