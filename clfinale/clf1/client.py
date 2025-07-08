import socket #enables tcp communication
from tkinter import * #used to build the GUI
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes # Crypto from pycryptodome, used for RSA key handling, AES, secure random key generation

class BobClient:
    def __init__(self, master):
        self.master = master #initialize the GUI
        master.title("Bob (Client)")

        self.text_area = Text(master) #text area to display sent messages
        self.text_area.pack()

        self.entry = Entry(master) #text input field for typing messages
        self.entry.pack()

        self.send_button = Button(master, text="Send", command=self.send_message) #send button that triggers send_message() when clicked
        self.send_button.pack()

    def send_message(self):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #creates a tcp socket
        client.connect(('localhost', 9999)) #connects to alice on port 9999

        public_key = RSA.import_key(client.recv(1024)) #receives Alice's RSA public key
        cipher_rsa = PKCS1_OAEP.new(public_key) #for secure encryption, the cipher object is wrapped using PKCS1_OAEP

        aes_key = get_random_bytes(16) #generates a random 16 byte AES key
        enc_aes_key = cipher_rsa.encrypt(aes_key) #encrypts it with Alice's public RSA key
        client.send(enc_aes_key) #sends the encrypted AES key to alice

        message = self.entry.get() #retrieves the message from the input field
        cipher_aes = AES.new(aes_key, AES.MODE_CFB) #creates an AES cipher in CFB mode using the generated key
        iv = cipher_aes.iv #extracts the IV
        ciphertext = cipher_aes.encrypt(message.encode()) #encrypts the message

        client.send(iv) #send the IV to alice
        client.send(ciphertext) #send the encrypted message to alice
        self.text_area.insert(END, f"You: {message}\n") #displays the sent message in the GUI
        client.close() #closes the socket connection

root = Tk() #initialzies the TKinter GUI
app = BobClient(root) #creates an instance of BobClient
root.mainloop() #starts the GUI event loop