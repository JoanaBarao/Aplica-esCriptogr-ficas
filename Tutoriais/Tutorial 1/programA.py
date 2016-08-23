import sys, os
from Crypto.Cipher import ARC4


if __name__ == "__main__":
    if len(sys.argv)<3:
        print("Error")

    elif len(sys.argv)==3 and sys.argv[1]=="-genkey":
        key=os.urandom(16)  # chave de 128 bits
        print("Key: "+key.encode("hex"))
        f=open(sys.argv[2],'wb')
        f.write(key)
        f.close()

    elif len(sys.argv)==5:
        key=open(sys.argv[2], "rb").read()
        text=open(sys.argv[3], "rb").read()
        if sys.argv[1]=='-enc':
            text=ARC4.new(key).encrypt(text)  # cifrar text com a chave dada
        elif sys.argv[1]=='-dec':
            text=ARC4.new(key).decrypt(text)  # decifrar text com a chave dada
        f=open(sys.argv[4],"wb")
        f.write(text)
        f.close()

    else:
        print("Error")
