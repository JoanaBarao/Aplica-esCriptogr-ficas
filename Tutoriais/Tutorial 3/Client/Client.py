import sys, os, socket
from Crypto.Cipher import ARC4
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

def key_derivation(password,salt):
	new=SHA256.new()
	nhash=password
	for i in range (1000):
		nhash+=salt+str(i)
		new.update(nhash)
		nhash=new.hexdigest()
	return nhash

def dec(password,enc_text):
	salt=enc_text[:16]
	text=enc_text[16:]
	nhash=key_derivation(password,salt)[:32]
	aes=AES.new(nhash[:16], AES.MODE_CBC,nhash[16:])
	return aes.decrypt(text)

if __name__ == "__main__":
	if len(sys.argv)!=4:
		print("Error")
		print("Client file host port")

	else:
		if (not os.path.exists("../LongTermKey")):
			print("Key file not found --> run Key_PBE in LongTermKeyFolder first")

		else:
			password=raw_input("Key passphrase: ")
			LongTermKey=open("../LongTermKey","r").read()
			LongTermKey=dec(password,LongTermKey)  # derivacao de uma chave atraves da passphrase

			SessionKey=os.urandom(16)  # nova chave de sessao a utilizar na comunicacao
			enc_SessionKey=ARC4.new(LongTermKey).encrypt(SessionKey)

			file=sys.argv[1]
			host=sys.argv[2]
			port=int(sys.argv[3])

			if (not os.path.exists("Files/"+file)):
				print("File not found: " + file)

			else:
				# ligacao com o servidor
				s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				s.connect((host, port))
				print("Connected to "+host+":"+str(port))

				s.send(enc_SessionKey)  # envio da chave de sessao cifrada com a chave derivada

				text=open("Files/"+file,"r").read()
				text=ARC4.new(SessionKey).encrypt(text)  # text cifrado com a chave de sessao

				total=0
				# envio do text (cifrado) em blocos de 1024 bytes
				while(total<len(text)):
					temp=text[total:total+1024]
					s.send(temp)
					total+=1024
				print("Sent file")
				s.close()
