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
	if len(sys.argv)!=3:
		print("Error")
		print("Server port uploadFolder")

	else:
		if (not os.path.exists("../LongTermKey")):
			print("Key file not found --> run Key_PBE in LongTermKeyFolder first")

		else:
			password=raw_input("Key passphrase: ")
			LongTermKey=open("../LongTermKey","r").read()
			LongTermKey=dec(password,LongTermKey)  # derivacao de uma chave atraves da passphrase

			port=int(sys.argv[1])
			folder=sys.argv[2]

			if (not os.path.exists(folder)):
				os.makedirs(folder)

			# criacao do canal
			s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			host=socket.gethostname()
			s.bind((host,port))
			print("Server started " + host + ":" + str(port))
			s.listen(1)

			# recepcao dos blocos de 1024 bytes cifrados
			nfiles=0
    		while True:
				(client,address)=s.accept()  # ligacao com o cliente

				SessionKey=client.recv(16)
				SessionKey=ARC4.new(LongTermKey).decrypt(SessionKey) # nova chave de sessao utilizada pelo cliente

				text=''
				while True:
					temp=client.recv(1024)  # recepcao bloco a bloco
					text+=temp
					if (len(temp) == 0):
						break
				nfiles+=1
				text=ARC4.new(SessionKey).decrypt(text)  # decifrar o text com a chave de sessao
				f=open(folder+"/file"+str(nfiles),"w")
				f.write(text)
				f.close()
				print("Upload to \'"+folder+"\' complete - file"+str(nfiles))
