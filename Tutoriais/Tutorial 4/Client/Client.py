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

				randClient=str(os.urandom(16))
				s.send(randClient)  # envio de um numero aleatorio gerado pelo cliente
				randServer=s.recv(16)  # recepcao de um numero aleatorio gerado pelo servidor

				new=SHA256.new(SessionKey+randClient+randServer)
				MasterKey=new.hexdigest()  # MasterKey de onde vamos derivar as chaves, os ivs e os macs
				keyDerv=masterKeyDerivation(MasterKey,SessionID)

				text=open("Files/"+file,"r").read()
				counter=Counter.new(128)
				mac,keySession,iv=keyDerv[0]  # para ficheiros enviados do servidor para o cliente usa-se keyDerv[1]
				cipher=AES.new(keySession,AES.MODE_CTR,iv,counter)  # cifra com a chave e iv apropriados

				macSeq=0
				total=0
				while(total<len(text)):
					temp=text[total:total+1024]
					enc=cipher.encrypt(temp)  # text cifrado
					new=hmac.new(enc+mac+str(macSeq))
					tag=new.hexdigest()  # tag com a informacao do mac e do numero de sequencia do mac
					s.send(tag+enc)  # envio de um bloco com a tag e o text cifrado
					macSeq+=1
					total+=1024
				print("Sent file")
