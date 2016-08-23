import sys, os, socket
from Crypto.Cipher import ARC4
from Crypto.Cipher import AES
import timeit

def cipherEnc(cipher,key,text):
	if cipher=='RC4':
		print("Using RC4 cipher to encrypt")
		return ARC4.new(key).encrypt(text)
	elif cipher=='AES/CBC/NoPadding':
		print("Using AES/CBC/NoPadding cipher to encrypt")
		text+='\x00'*(16-len(text)%16)  # padding
		return AES.new(key,AES.MODE_CBC,'0'*16).encrypt(text)
	elif cipher=='AES/CBC/PKCS5Padding':
		print("Using AES/CBC/PKCS5Padding cipher to encrypt")
		text+=(16-len(text)%16)*chr(16-len(text)%16)  # pkcs5 padding
		return AES.new(key,AES.MODE_CBC,'0'*16).encrypt(text)
	elif cipher=='AES/CFB8/PKCS5Padding':
		print("Using AES/CFB8/PKCS5Padding cipher to encrypt")
		text+=(16-len(text)%16)*chr(16-len(text)%16)  # pkcs5 padding
		return AES.new(key,AES.MODE_CFB,'0'*16,segment_size=8).encrypt(text)
	elif cipher=='AES/CFB8/NoPadding':
		print("Using AES/CFB8/NoPadding cipher to encrypt")
		text+='\x00'*(16-len(text)%16)  # padding
		return AES.new(key,AES.MODE_CFB,'0'*16,segment_size=8).encrypt(text)
	elif cipher=='AES/CFB/NoPadding':
		print("Using AES/CFB/NoPadding cipher to encrypt")
		text+='\x00'*(16-len(text)%16)  # padding
		return AES.new(key,AES.MODE_CFB,'0'*16).encrypt(text)
	else:
		print("Invalid Cipher --> exit connection")
		sys.exit()


if __name__ == "__main__":
	if len(sys.argv)!=5:
		print("Error")
		print("Client file host port cipher")

	else:
		if (not os.path.exists("key")):
			print("Key file not found --> run GenKey first")

		else:
			start = timeit.default_timer()

			key=open("key","rb").read()

			file=sys.argv[1]
			host=sys.argv[2]
			port=int(sys.argv[3])
			cipher=sys.argv[4]

			if (not os.path.exists("Files/"+file)):
				print("File not found: " + file)

			else:
				# ligacao com o servidor
				s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				s.connect((host, port))
				print("Connected to "+host+":"+str(port))

				text=open("Files/"+file,"r").read()
				text=cipherEnc(cipher,key,text)  # cifrar o text

				total=0
				# envio do text (cifrado) em blocos de 1024 bytes
				while(total<len(text)):
					temp=text[total:total+1024]
					s.send(temp)
					total+=1024
				print("Sent file")
				s.close()

			stop = timeit.default_timer()
			sys.stderr.write('Time: '+str(stop - start)+'\n')
