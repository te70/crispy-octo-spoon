import socket, threading, os
from tkinter import *
from tkinter import filedialog
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

def encrypt_message(aes_key, message):
    cipher = AES.new(aes_key, AES.MODE_CFB)
    return cipher.iv, cipher.encrypt(message.encode())

def decrypt_message(aes_key, iv, ciphertext):
    cipher = AES.new(aes_key, AES.MODE_CFB, iv=iv)
    return cipher.decrypt(ciphertext).decode()

def encrypt_file(aes_key, file_data):
    cipher = AES.new(aes_key, AES.MODE_CFB)
    return cipher.iv, cipher.encrypt(file_data)

def decrypt_file(aes_key, iv, encrypted_data):
    cipher = AES.new(aes_key, AES.MODE_CFB, iv=iv)
    return cipher.decrypt(encrypted_data)


class AliceServer:
    def __init__(self, master):
        self.master = master
        master.title("Alice (Server)")

        self.text_area = Text(master)
        self.text_area.pack()

        self.entry = Entry(master)
        self.entry.pack()

        self.send_button = Button(master, text="Send", command=self.send_message)
        self.send_button.pack()

        self.file_button = Button(master, text="Upload File", command=self.send_file)
        self.file_button.pack()

        #generate RSA key pait for secure key exchange
        self.key = RSA.generate(1024)
        self.private_key = self.key
        self.public_key = self.key.publickey()

        #print RSA keys to console for reference
        print("RSA Public Key:")
        print(self.public_key.publickey().export_key().decode())

        print("RSA Private Key:")
        print(self.private_key.export_key().decode())

        #start server in a separate thread to avoid blocking GUI
        threading.Thread(target=self.start_server).start()

    #start tcp server and handle rsa key exchange
    def start_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('localhost', 9994)) #bind to port 9994
        server.listen(1) #listen to one connection
        self.text_area.insert(END, "Waiting for Bob...\n")
        self.conn, _ = server.accept() #accept connection from Bob
        self.text_area.insert(END, "Bob connected.\n")

        self.conn.send(self.public_key.export_key()) #send RSA public key to Bob

        #receive encrypted AES session key from Bob
        enc_key = self.conn.recv(128)
        cipher_rsa = PKCS1_OAEP.new(self.private_key)
        self.aes_key = cipher_rsa.decrypt(enc_key) #decrypt AES key using RSA private key

        print("\n AES Key:")
        print(self.aes_key.hex())

        #start thread to receive messages and files
        threading.Thread(target=self.receive_messages).start()

    #send encrypred message to Bob
    def send_message(self):
        message = self.entry.get()
        iv, ciphertext = encrypt_message(self.aes_key, message)
        self.conn.send(b'MSG') #message type identifer
        self.conn.send(iv) #send IV
        self.conn.send(ciphertext) #send encrypted messsage
        self.text_area.insert(END, f"You: {message}\n") #display sent message

    #send encrypted file to Bob
    def send_file(self):
        filepath = filedialog.askopenfilename() #open file dialog
        if filepath:
            filename = os.path.basename(filepath).encode() #get filename
            with open(filepath, 'rb') as f:
                file_data = f.read() #read file content
            iv, encrypted_file = encrypt_file(self.aes_key, file_data)
            sock = self.conn if hasattr(self, 'conn') else self.client
            sock.send(b'FILE') #file type identifier
            sock.send(len(filename).to_bytes(2, 'big')) #send filename length
            sock.send(filename) #send filename
            sock.send(iv) #send IV
            sock.send(encrypted_file) #send encrypred file content
            self.text_area.insert(END, f"Sent file: {filepath}\n")

    #receive messages and files from Bob
    def receive_messages(self):
        while True:
            try:
                #determine message type
                msg_type = self.conn.recv(4) if hasattr(self, 'conn') else self.client.recv(4)

                if msg_type == b'MSG':
                    #receive and decrypt message
                    iv = (self.conn if hasattr(self, 'conn') else self.client).recv(16)
                    data = (self.conn if hasattr(self, 'conn') else self.client).recv(4096)
                    message = decrypt_message(self.aes_key, iv, data)
                    self.text_area.insert(END, f"{'Bob' if hasattr(self, 'conn') else 'Alice'}: {message}\n")

                elif msg_type == b'FILE':
                    #receive and decrypt file
                    sock = self.conn if hasattr(self, 'conn') else self.client
                    name_len = int.from_bytes(sock.recv(2), 'big') #filename length
                    filename = sock.recv(name_len).decode() #filename
                    iv = sock.recv(16) #IV
                    encrypted_data = sock.recv(4096) #encrypted file content
                    file_content = decrypt_file(self.aes_key, iv, encrypted_data)

                    #save file to downloads folder
                    os.makedirs("downloads", exist_ok=True)
                    save_path = os.path.join("downloads", filename)
                    with open(save_path, 'wb') as f:
                        f.write(file_content)
                    self.text_area.insert(END, f"Auto-saved file to: {save_path}\n")

            except Exception as e:
                print(f"Error: {e}")
                break

#initialize and run
root = Tk()
app = AliceServer(root)
root.mainloop()