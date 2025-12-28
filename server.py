"""
Secure Chat Server
Simplified and Robust Implementation
"""
import socket
import threading
import json
import os
import time
from steganography import extract_password, load_image_to_array
from crypto import decrypt_message, encrypt_message

class ChatServer:
    def __init__(self, host='localhost', port=8888):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # User data: {username: {'password': ..., 'online': bool, 'socket': socket}}
        # Note: We enforce single active login per user for simplicity
        self.users = {}
        
        # Offline messages: {username: [{'sender': ..., 'message': ...}]}
        self.offline_messages = {}
        
        self.data_dir = "server_data"
        self.ensure_directories()
        self.load_users()

    def ensure_directories(self):
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
            os.makedirs(os.path.join(self.data_dir, "photos"))
            os.makedirs(os.path.join(self.data_dir, "embedded_photos"))

    def load_users(self):
        users_file = os.path.join(self.data_dir, "users.json")
        if os.path.exists(users_file):
            try:
                with open(users_file, 'r') as f:
                    users_data = json.load(f)
                    for username, data in users_data.items():
                        self.users[username] = {
                            'password': self.recover_password(data.get('embedded_photo_path')),
                            'photo_path': data.get('photo_path'),
                            'embedded_photo_path': data.get('embedded_photo_path'),
                            'online': False,
                            'socket': None
                        }
            except Exception as e:
                print(f"Error loading users: {e}")

    def recover_password(self, embedded_path):
        if embedded_path and os.path.exists(embedded_path):
            try:
                arr = load_image_to_array(embedded_path)
                return extract_password(arr)
            except:
                return None
        return None

    def save_users(self):
        users_file = os.path.join(self.data_dir, "users.json")
        data_to_save = {}
        for username, user in self.users.items():
            data_to_save[username] = {
                'photo_path': user['photo_path'],
                'embedded_photo_path': user['embedded_photo_path']
            }
        try:
            with open(users_file, 'w') as f:
                json.dump(data_to_save, f, indent=2)
        except Exception as e:
            print(f"Error saving users: {e}")

    def start(self):
        try:
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            print(f"Server listening on {self.host}:{self.port}")
            while True:
                client_sock, addr = self.socket.accept()
                print(f"New connection: {addr}")
                threading.Thread(target=self.handle_client, args=(client_sock,), daemon=True).start()
        except Exception as e:
            print(f"Server startup error: {e}")
        finally:
            self.socket.close()

    def send_json(self, sock, data):
        try:
            json_str = json.dumps(data)
            bytes_data = json_str.encode('utf-8')
            length = len(bytes_data).to_bytes(4, 'big')
            sock.sendall(length + bytes_data)
            return True
        except:
            return False

    def recv_json(self, sock):
        try:
            length_bytes = sock.recv(4)
            if not length_bytes: return None
            length = int.from_bytes(length_bytes, 'big')
            data = b''
            while len(data) < length:
                chunk = sock.recv(length - len(data))
                if not chunk: return None
                data += chunk
            return json.loads(data.decode('utf-8'))
        except:
            return None

    def handle_client(self, sock):
        current_user = None
        try:
            while True:
                req = self.recv_json(sock)
                if not req: break
                
                command = req.get('command')
                
                if command == 'REGISTER':
                    self.handle_register(sock, req)
                elif command == 'LOGIN':
                    username = self.handle_login(sock, req)
                    if username: current_user = username
                elif command == 'SEND_MESSAGE':
                    self.handle_message(sock, req, current_user)
                elif command == 'GET_USERS':
                    self.handle_get_users(sock)
                elif command == 'LOGOUT':
                    break
        except Exception as e:
            print(f"Client error: {e}")
        finally:
            if current_user:
                print(f"{current_user} disconnected")
                if current_user in self.users:
                    self.users[current_user]['online'] = False
                    self.users[current_user]['socket'] = None
            sock.close()

    def handle_register(self, sock, req):
        username = req.get('username')
        photo_data_hex = req.get('photo_data') # Expecting hex string for binary data
        embedded_data_hex = req.get('embedded_data')
        
        if username in self.users:
            self.send_json(sock, {'status': 'error', 'message': 'Username taken'})
            return

        try:
            # Save files
            photo_bytes = bytes.fromhex(photo_data_hex)
            embedded_bytes = bytes.fromhex(embedded_data_hex)
            
            photo_path = os.path.join(self.data_dir, "photos", f"{username}.png")
            embedded_path = os.path.join(self.data_dir, "embedded_photos", f"{username}_embedded.png")
            
            with open(photo_path, 'wb') as f: f.write(photo_bytes)
            with open(embedded_path, 'wb') as f: f.write(embedded_bytes)
            
            # Extract password
            pwd = self.recover_password(embedded_path)
            if not pwd:
                self.send_json(sock, {'status': 'error', 'message': 'Could not extract password from image'})
                return

            self.users[username] = {
                'password': pwd,
                'photo_path': photo_path,
                'embedded_photo_path': embedded_path,
                'online': False,
                'socket': None
            }
            self.save_users()
            self.send_json(sock, {'status': 'success', 'message': 'Registered successfully'})
            print(f"Registered {username}")
        except Exception as e:
            self.send_json(sock, {'status': 'error', 'message': str(e)})

    def handle_login(self, sock, req):
        username = req.get('username')
        password = req.get('password')
        
        if username not in self.users:
            self.send_json(sock, {'status': 'error', 'message': 'User not found'})
            return None
        
        real_pwd = self.users[username]['password']
        if password != real_pwd:
            self.send_json(sock, {'status': 'error', 'message': 'Invalid password'})
            return None
            
        self.users[username]['online'] = True
        self.users[username]['socket'] = sock
        self.send_json(sock, {'status': 'success', 'message': 'Logged in'})
        print(f"{username} logged in")
        
        # Send offline messages
        if username in self.offline_messages:
            for msg in self.offline_messages[username]:
                # Re-encrypt for receiver is already done or done here?
                # Better to store raw message and re-encrypt on send, OR store doubly encrypted?
                # Simplify: The message in offline_queue is ALREADY re-encrypted for the receiver
                # Wait, if we decrypt from sender and encrypt for receiver ON SEND, we need receiver's password.
                # We have receiver's password in self.users.
                # Let's see how invalid message handling:
                # 1. Receiver online: decrypt(sender_key) -> encrypt(receiver_key) -> send
                # 2. Receiver offline: decrypt(sender_key) -> encrypt(receiver_key) -> store
                self.send_json(sock, {
                    'type': 'MESSAGE',
                    'sender': msg['sender'],
                    'message': msg['message'],
                    'timestamp': msg['timestamp']
                })
            del self.offline_messages[username]
            
        return username

    def handle_message(self, sock, req, sender_username):
        if not sender_username:
            self.send_json(sock, {'status': 'error', 'message': 'Not logged in'})
            return

        target_username = req.get('target')
        encrypted_msg = req.get('message')
        
        if target_username not in self.users:
            self.send_json(sock, {'status': 'error', 'message': 'User not found'})
            return

        try:
            # 1. Decrypt using sender's password
            sender_pwd = self.users[sender_username]['password']
            decrypted = decrypt_message(encrypted_msg, sender_pwd)
            
            # 2. Encrypt using receiver's password
            receiver_pwd = self.users[target_username]['password']
            re_encrypted = encrypt_message(decrypted, receiver_pwd)
            
            timestamp = time.strftime("%H:%M")
            msg_payload = {
                'type': 'MESSAGE',
                'sender': sender_username,
                'message': re_encrypted,
                'timestamp': timestamp
            }
            
            # 3. Send or Store
            receiver_sock = self.users[target_username]['socket']
            sent = False
            if self.users[target_username]['online'] and receiver_sock:
                if self.send_json(receiver_sock, msg_payload):
                    sent = True
                else:
                    # Socket failed, mark offline
                    self.users[target_username]['online'] = False
                    self.users[target_username]['socket'] = None
            
            if not sent:
                if target_username not in self.offline_messages:
                    self.offline_messages[target_username] = []
                self.offline_messages[target_username].append({
                    'sender': sender_username,
                    'message': re_encrypted,
                    'timestamp': timestamp
                })
                self.send_json(sock, {'status': 'success', 'message': 'Message queued (User offline)'})
            else:
                self.send_json(sock, {'status': 'success', 'message': 'Message sent'})
                
        except Exception as e:
            print(f"Message relay error: {e}")
            self.send_json(sock, {'status': 'error', 'message': 'Encryption error'})

    def handle_get_users(self, sock):
        user_list = []
        for uname, udata in self.users.items():
            user_list.append({
                'username': uname,
                'online': udata['online']
            })
        self.send_json(sock, {'type': 'USER_LIST', 'users': user_list})

if __name__ == "__main__":
    server = ChatServer()
    server.start()
