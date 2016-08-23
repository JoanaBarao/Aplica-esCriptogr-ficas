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

	if len(sys.argv)!=3:
		print("Error")
		print("Server port uploadFolder")

	else:
		port=int(sys.argv[1])
		folder=sys.argv[2]

		if (not os.path.exists(folder)):
			os.makedirs(folder)

		# criacao do canal
		ss=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		host=socket.gethostname()
		ss.bind((host,port))
		print("Server started " + host + ":" + str(port))
		ss.listen(1)

		nfiles=0
    	while True:
			(client,address)=ss.accept()  # ligacao com o cliente

			# gerar par de chaves RSA do servidor
			random=Random.new().read
			ServerPrivateKey=RSA.generate(2048,random)
			ServerPublicKey=ServerPrivateKey.publickey().exportKey("PEM")

			client.sendall(ServerPublicKey)  # envio da chave publica do servidor
			MasterKey=client.recv(256)  # nova MasterKey utilizada pelo servidor
			MasterKey=ServerPrivateKey.decrypt(MasterKey)  # MasterKey de onde vamos derivar as chaves, os ivs e os macs
			keyDerv=masterKeyDerivation(MasterKey,SessionID)
			print("Handshake complete")

			counter=Counter.new(128)
			mac,keySession,iv=keyDerv[0]  # para ficheiros enviados do servidor para o cliente usa-se keyDerv[1]
			cipher = AES.new(keySession,AES.MODE_CTR,iv,counter)  # cifra com a chave e iv apropriados

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
