import socket, threading, os #socket for networking, threading for concurrency, os for file handling
from tkinter import * # GUI
from tkinter import filedialog # GUI file selection
from Crypto.PublicKey import RSA #rsa key generation
from Crypto.Cipher import PKCS1_OAEP, AES # encryption algorithms
from Crypto.Random import get_random_bytes #secure random byte generator

#encrypt a text message using AES in CFB mode
def encrypt_message(aes_key, message):
    cipher = AES.new(aes_key, AES.MODE_CFB)
    return cipher.iv, cipher.encrypt(message.encode())

#decrypt a text message using AES and the provided IV
def decrypt_message(aes_key, iv, ciphertext):
    cipher = AES.new(aes_key, AES.MODE_CFB, iv=iv)
    return cipher.decrypt(ciphertext).decode()

#encrypt file data using AES
def encrypt_file(aes_key, file_data):
    cipher = AES.new(aes_key, AES.MODE_CFB)
    return cipher.iv, cipher.encrypt(file_data)

#decrypt file data using AES
def decrypt_file(aes_key, iv, encrypted_data):
    cipher = AES.new(aes_key, AES.MODE_CFB, iv=iv)
    return cipher.decrypt(encrypted_data)


class BobClient:
    def __init__(self, master):
        self.master = master #GUI setup
        master.title("Bob (Client)") 

        self.text_area = Text(master) 
        self.text_area.pack()

        self.entry = Entry(master)
        self.entry.pack()

        self.send_button = Button(master, text="Send", command=self.send_message)
        self.send_button.pack()

        self.file_button = Button(master, text="Upload File", command=self.send_file)
        self.file_button.pack()

        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #create tcp socket
        self.client.connect(('localhost', 9994)) #connect to alice on port 9994

        public_key = RSA.import_key(self.client.recv(1024)) #receive alice rsa public key
        cipher_rsa = PKCS1_OAEP.new(public_key) #create rsa cipher object
        self.aes_key = get_random_bytes(16) #generate aes session key
        enc_key = cipher_rsa.encrypt(self.aes_key) #encrypt aes key with alice's public rsa key
        self.client.send(enc_key) #send encrypred aes key to alice

        threading.Thread(target=self.receive_messages).start() #start background thread to receive messages

    def send_message(self):
        message = self.entry.get() #get message from input field
        iv, ciphertext = encrypt_message(self.aes_key, message) #encrypt message with AES
        self.client.send(b'MSG') #send message type identifier
        self.client.send(iv) #send AES IV
        self.client.send(ciphertext) #send encrypted message
        self.text_area.insert(END, f"You: {message}\n") #display sent message in text area

    def send_file(self):
        filepath = filedialog.askopenfilename() #open file picker
        if filepath:
            filename = os.path.basename(filepath).encode() #extract filename and encode it
            with open(filepath, 'rb') as f:
                file_data = f.read() #read file contents
            iv, encrypted_file = encrypt_file(self.aes_key, file_data) #encrypt file awith aes
            sock = self.conn if hasattr(self, 'conn') else self.client 
            sock.send(b'FILE') #send file type identifier
            sock.send(len(filename).to_bytes(2, 'big')) #send filename length (2 bytes)
            sock.send(filename) #send filename
            sock.send(iv) #send AES iv
            sock.send(encrypted_file) #send encrypted file data
            self.text_area.insert(END, f"Sent file: {filepath}\n") #log file sent


    def receive_messages(self):
        while True:
            try:
                #read message type (4 bytes): either 'MSG' or 'FILE'
                msg_type = self.conn.recv(4) if hasattr(self, 'conn') else self.client.recv(4)

                if msg_type == b'MSG':
                    iv = (self.conn if hasattr(self, 'conn') else self.client).recv(16) #receive IV
                    data = (self.conn if hasattr(self, 'conn') else self.client).recv(4096) #receive ciphertext
                    message = decrypt_message(self.aes_key, iv, data) #decrypt message
                    self.text_area.insert(END, f"{'Bob' if hasattr(self, 'conn') else 'Alice'}: {message}\n") #display message

                elif msg_type == b'FILE':
                    sock = self.conn if hasattr(self, 'conn') else self.client
                    name_len = int.from_bytes(sock.recv(2), 'big') #read filename length (2 bytes)
                    filename = sock.recv(name_len).decode() #read and decode filename
                    iv = sock.recv(16) #receive AES IV
                    encrypted_data = sock.recv(4096) #receive encrypted file data
                    file_content = decrypt_file(self.aes_key, iv, encrypted_data) #descrypt file

                    os.makedirs("downloads", exist_ok=True) #ensure downloads folder exists
                    save_path = os.path.join("downloads", filename) #build save path
                    with open(save_path, 'wb') as f:
                        f.write(file_content) #save file to disk
                    self.text_area.insert(END, f"Auto-saved file to: {save_path}\n") #log save location


            except Exception as e:
                print(f"Error: {e}") #print any errors
                break #exit loop on failure

root = Tk() #create main window
app = BobClient(root) #instantiate BobClient
root.mainloop() #start GUI event loop