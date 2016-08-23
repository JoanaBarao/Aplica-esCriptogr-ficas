import sys, os
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

# chave com password based encryption
# passphrase: ApCriptograficas2015

def key_derivation(password,salt):
	new=SHA256.new()
	nhash=password
	for i in range (1000):
		nhash+=salt+str(i)
		new.update(nhash)
		nhash=new.hexdigest()
	return nhash

def enc(password,text):
	salt=os.urandom(16)  # aleatoriedade
	nhash=key_derivation(password,salt)[:32]
	aes=AES.new(nhash[:16], AES.MODE_CBC,nhash[16:])
	return salt+aes.encrypt(text)

def dec(password,enc_text):
	salt=enc_text[:16]
	text=enc_text[16:]
	nhash=key_derivation(password,salt)[:32]
	aes=AES.new(nhash[:16], AES.MODE_CBC,nhash[16:])
	return aes.decrypt(text)

if __name__ == "__main__":
	if len(sys.argv)!=1:
		print("Error")
		print("LongTermKey_PBE")
		sys.exit()

	else:
		key=os.urandom(16)
		password=raw_input("Key passphrase: ")
		enc_key=enc(password,key)  # chave cifrada com uma passphrase
		print("Long Term Key: "+enc_key.encode("hex"))
		f=open("LongTermKey","w")
		f.write(enc_key)
		f.close()
