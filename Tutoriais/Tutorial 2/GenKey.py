import sys, os

# gerar chave

if __name__ == "__main__":
	if len(sys.argv)!=2:
		print("Error")
		print("GenKey file")
		sys.exit()

	else:
		key=os.urandom(16)  # chave de 128 bits
		print("Key: "+key.encode("hex"))
    	f = open("key","wb")
    	f.write(key)
    	f.close()
