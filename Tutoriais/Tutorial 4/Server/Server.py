import sys, os, socket, hmac
from Crypto.Cipher import ARC4
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util import Counter

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

def masterKeyDerivation(key,SessionID):
	new=SHA256.new()
	new.update(key+str(SessionID)+'A')
	macA,macB=new.hexdigest()[:32],new.hexdigest()[32:]
	new.update(key+str(SessionID)+'B')
	keySessionA,keySessionB=new.hexdigest()[:32],new.hexdigest()[32:]
	new.update(key+str(SessionID)+'C')
	ivA,ivB=new.hexdigest()[:32],new.hexdigest()[32:]
	return ([macA,keySessionA,ivA],[macB,keySessionB,ivB])


if __name__ == "__main__":
	SessionID=0

	if len(sys.argv)!=3:
		print("Error")
		print("Server port uploadFolder")

	else:
		if (not os.path.exists("../LongTermKey")):
			print("Key file not found --> run Key_PBE in LongTermKeyFolder first")
			sys.exit()

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

			nfiles=0
    		while True:
				(client,address)=s.accept()  # ligacao com o cliente

				SessionKey=client.recv(16)
				SessionKey=ARC4.new(LongTermKey).decrypt(SessionKey)  # nova chave de sessao utilizada pelo cliente

				randServer=str(os.urandom(16))
				randClient=client.recv(16)  # recepcao de um numero aleatorio gerado pelo cliente
				client.sendall(randServer)  # envio de um numero aleatorio gerado pelo servidor

				new=SHA256.new(SessionKey+randClient+randServer)
				MasterKey=new.hexdigest()  # MasterKey de onde vamos derivar as chaves, os ivs e os macs
				keyDerv=masterKeyDerivation(MasterKey,SessionID)

				counter=Counter.new(128)
				mac,keySession,iv=keyDerv[0]  # para ficheiros enviados do servidor para o cliente usa-se keyDerv[1]
				cipher=AES.new(keySession,AES.MODE_CTR,iv,counter)  # cifra com a chave e iv apropriados

				macSeq=0
				text=''
				while True:
					temp=client.recv(32+1024)
					if (len(temp) == 0):
						break
					tag,enc=temp[:32],temp[32:]
					new=hmac.new(enc+mac+str(macSeq))
					tagS=new.hexdigest()
					if tag==tagS:  # se a tag se verificar deciframos o bloco
						dec=cipher.decrypt(enc)
						text+=dec
						macSeq+=1
					else:  # caso contrario o bloco e ignorado
						print("Invalid MAC")

				if text!='':  # se algum ficheiro (ou parte) for recebido guardamo-lo
					nfiles+=1
					f=open(folder+"/file"+str(nfiles),"w")
					f.write(text)
					f.close()
					print("Upload to \'"+folder+"\' complete - file"+str(nfiles))
				else:
					print("Error receiving file")
