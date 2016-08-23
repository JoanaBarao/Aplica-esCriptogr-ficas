import sys, os, socket
from Crypto.Cipher import ARC4
from Crypto.Cipher import AES
import timeit

def cipherDec(cipher,key,text):
	if cipher=='RC4':
		print("Using RC4 cipher to decrypt")
		return ARC4.new(key).decrypt(text)
	elif cipher=='AES/CBC/NoPadding':
		print("Using AES/CBC/NoPadding cipher to decrypt")
		text=AES.new(key,AES.MODE_CBC,'0'*16).decrypt(text)
		while text[-1]=='\x00':
			text=text[:-1]  # retirar o padding
		return text
	elif cipher=='AES/CBC/PKCS5Padding':
		print("Using AES/CBC/PKCS5Padding cipher to decrypt")
		text=AES.new(key,AES.MODE_CBC,'0'*16).decrypt(text)
		return text[0:-ord(text[-1])]  # retirar o padding
	elif cipher=='AES/CFB8/PKCS5Padding':
		print("Using AES/CFB8/PKCS5Padding cipher to decrypt")
		text=AES.new(key,AES.MODE_CFB,'0'*16,segment_size=8).decrypt(text)
		return text[0:-ord(text[-1])]  # retirar o padding
	elif cipher=='AES/CFB8/NoPadding':
		print("Using AES/CFB8/NoPadding cipher to decrypt")
		text=AES.new(key,AES.MODE_CFB,'0'*16,segment_size=8).decrypt(text)
		while text[-1]=='\x00':
			text=text[:-1]  # retirar o padding
		return text
	elif cipher=='AES/CFB/NoPadding':
		print("Using AES/CFB/NoPadding cipher to decrypt")
		text=AES.new(key,AES.MODE_CFB,'0'*16).decrypt(text)
		while text[-1]=='\x00':
			text=text[:-1]  # retirar o padding
		return text
	else:
		print("Invalid Cipher --> exit connection")
		sys.exit()


if __name__ == "__main__":
	if len(sys.argv)!=4:
		print("Error")
		print("Server port uploadFolder cipher")

	else:
		if (not os.path.exists("key")):
			print("Key file not found --> run GenKey first")
		else:
			key=open("key","rb").read()

			port=int(sys.argv[1])
			folder=sys.argv[2]
			cipher=sys.argv[3]

			if (not os.path.exists(folder)):
				os.makedirs(folder)

			# criacao do canal
			s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			host=socket.gethostname()
			s.bind((host, port))
			print("Server started "+host+":"+str(port))
			s.listen(1)

			# recepcao dos blocos de 1024 bytes cifrados
			nfiles=0
    		while True:
				(client,address)=s.accept()  # ligacao com o cliente
				start = timeit.default_timer()
				text=''
				while True:
					temp=client.recv(1024)  # recepcao bloco a bloco
					if (len(temp)==0):
						break
					text+=temp
				nfiles+=1
				text=cipherDec(cipher,key,text)  # decifrar o text
				f=open(folder+"/file"+str(nfiles),"w")
				f.write(text)
				f.close()
				print("Upload to \'"+folder+"\' complete - file"+str(nfiles))

				stop = timeit.default_timer()
				sys.stderr.write('Time: '+str(stop - start)+'\n')
