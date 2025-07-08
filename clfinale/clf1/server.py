import socket, threading #socket enables tcp communication while threading allows the server to run in the background
from tkinter import * #use to build the GUI
from Crypto.PublicKey import RSA #Crypto from pycryptodome used for RSA key generation, encryption/decryption, AES
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

class AliceServer:
    def __init__(self, master):
        self.master = master #intializes the GUI window
        master.title("Alice (Server)")

        self.text_area = Text(master) #adds a text area to display messages
        self.text_area.pack()

        self.start_button = Button(master, text="Start server", command=self.start_server) #adds a button to start the server
        self.start_button.pack()

        #generate rsa key pair
        self.key = RSA.generate(1024) #generates a 1024 bit RSA key pair
        self.private_key = self.key #store private key
        self.public_key = self.key.publickey() #store public key

        #print keys to terminal
        print("Private key:")
        print(self.private_key.export_key().decode()) 
        print("Public key:")
        print(self.public_key.export_key().decode())
        
    
    def start_server(self): #starts the sever in a new thread so the GUI remains responsive
        threading.Thread(target=self.server_thread).start()
    
    def server_thread(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #creates a TCP socket
        server.bind(('localhost', 9999)) #binds it to localhost on port 9999
        server.listen(1) # listens for one incoming connection
        self.text_area.insert(END, "Waiting for Bob...\n") #displays status in the GUI
        conn, _ = server.accept() #accepts a connection from Bob
        self.text_area.insert(END, "Bob connected. \n")

        conn.send(self.public_key.export_key()) #sends alice's public RSA key to Bob

        enc_aes_key = conn.recv(128) #receives the AES key encrypted with Alice's public key
        cipher_rsa = PKCS1_OAEP.new(self.private_key) 
        aes_key = cipher_rsa.decrypt(enc_aes_key) #decrypts it using Alice's private key

        iv = conn.recv(16) #receives the AES IV and ciphertext from Bob
        ciphertext = conn.recv(1024)
        cipher_aes = AES.new(aes_key, AES.MODE_CFB, iv=iv)
        plaintext = cipher_aes.decrypt(ciphertext) #decrypts the message using the shared AES key

        self.text_area.insert(END, f"Bob: {plaintext.decode()}\n") #displays the decrypted message in the GUI
        
        conn.close() #closes the connection

root = Tk() #intializes the Tkinter GUI
app = AliceServer(root) #creates an instance of AliceServer
root.mainloop() #starts the GUI event loop