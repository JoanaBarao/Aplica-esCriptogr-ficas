import sys, os

def RC4(key,string):
    # key-scheduling algorithm (KSA)
    S=range(256)
    j=0
    for i in range(256):
        j=(j+S[i]+ord(key[i%len(key)]))&255
        S[i],S[j]=S[j],S[i]
    # Pseudo-random generation algorithm (PRGA)
    new=''
    i=0
    j=0
    for c in string:
        i=(i+1)&255
        j=(j+S[i])&255
        S[i],S[j]=S[j],S[i]
        k=S[(S[i]+S[j])&255]
        new+=chr(ord(c)^k)
    return new


if __name__ == "__main__":
    if len(sys.argv)<3:
        print("Error")

    elif len(sys.argv)==3 and sys.argv[1]=="-genkey":
        key=os.urandom(16)  # chave de 128 bits
        print("Key: "+key.encode("hex"))
        f=open(sys.argv[2],'wb')
        f.write(key)
        f.close()

    elif len(sys.argv)==5 and (sys.argv[1]=='-enc' or sys.argv[1]=='-dec'):
        key=open(sys.argv[2], "rb").read()
        text=open(sys.argv[3], "rb").read()
        text=RC4(key,text)  # cifrar/decifrar text com a chave dada
        f=open(sys.argv[4],"wb")
        f.write(text)
        f.close()

    else:
        print("Error")
