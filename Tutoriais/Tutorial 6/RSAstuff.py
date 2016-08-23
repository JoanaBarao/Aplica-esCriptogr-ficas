import sys
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto import Random


if __name__ == "__main__":
    if len(sys.argv)<3:
        print('Error')
        print('RSAstuff -genkey file')
        print('RSAstuff -sign FileTrustedAutPrivKey FileSomePubKey ')

    elif sys.argv[1]=='-genkey':
        random=Random.new().read
        new=RSA.generate(2048,random)  # par de chaves RSA de 2048 bits
        PublicKey=new.publickey().exportKey("PEM")  # chave publica
        PrivateKey=new.exportKey("PEM")  # chave privada
        f=open(sys.argv[2]+'.pub','w')
        f.write(PublicKey)
        f.close()
        f=open(sys.argv[2]+'.priv','w')
        f.write(PrivateKey)
        f.close()

    elif sys.argv[1]=='-sign':
        AutKey=open(sys.argv[2],'r').read()  # chave privada da entidade confiavel
        AutKey=RSA.importKey(AutKey)
        SomeKey=open(sys.argv[3],'r').read()  # chave publica que queremos assinar
        SomeKey=RSA.importKey(SomeKey).exportKey("PEM")
        new=SHA256.new(SomeKey).hexdigest()
        sign=AutKey.sign(new,0)[0]  # assinatura da chave
        f=open(sys.argv[3]+'.sign','w')
        f.write(str(sign))
        f.close()
