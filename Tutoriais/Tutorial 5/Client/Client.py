import sys, os, socket, hmac
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.PublicKey import RSA
from Crypto import Random

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
		file = sys.argv[1]
		host = sys.argv[2]
		port = int(sys.argv[3])

		if (not os.path.exists("Files/"+file)):
			print("File not found: " + file)

		else:
			# ligacao com o servidor
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((host, port))
			print("Connected to "+host+":"+str(port))

			ServerPublicKey=RSA.importKey(s.recv(450))  # recepcao da chave publica do servidor
			MasterKey=os.urandom(16)  # nova MasterKey a utilizar na comunicacao
			encMasterKey=ServerPublicKey.encrypt(MasterKey,0)[0]
			s.send(encMasterKey)  # envio da MasterKey cifrada com a chave publica do servidor

			keyDerv=masterKeyDerivation(MasterKey,SessionID)
			print("Handshake complete")

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
			s.close()
