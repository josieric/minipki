#! /opt/conda/bin/python
# -*- coding: utf-8 -*-

import os,rsa,base64,inspect
import hashlib
import logging

class crypto:
    def __init__( self, dirname:str = "", size:int = 2048, pub_only:bin = False, fn_pub:str = "crypto_rsa.pub", fn_key:str = "crypto_rsa.key"):
       self.pub_only = pub_only
       if not os.path.isdir(dirname):
         dirname = os.path.dirname( inspect.getfile(crypto) )
       keyfile= os.path.join(dirname,fn_key) if not pub_only else None
       pubfile= os.path.join(dirname,fn_pub)
       if not pub_only and os.path.isfile(keyfile):
           with open(keyfile,"rb") as f:
             self.privateKey = rsa.PrivateKey.load_pkcs1(f.read())
       if os.path.isfile(pubfile):
           with open(pubfile,"rb") as f:
             self.publicKey= rsa.PublicKey.load_pkcs1(f.read())
       elif pub_only:
         raise Exception("Can't generate public key only !!") 
       else:
         self.publicKey, self.privateKey = rsa.newkeys(size)
         with open(keyfile,"wb") as f:
           self.privateKey= f.write(self.privateKey.save_pkcs1())
         with open(pubfile,"wb") as f:
           self.publicKey= f.write(self.publicKey.save_pkcs1())
       logging.debug(f"Load private:{keyfile} public:{pubfile}")

    def encrypt( self, msg:str ):
        return base64.b64encode(rsa.encrypt(msg.encode(),self.publicKey)).decode()
    def decrypt( self, enc:str ):
        if self.pub_only:
          raise Exception("Can't decrypt in pub_only !!")
        else:
          return rsa.decrypt(base64.b64decode(enc), self.privateKey).decode()

    def sign( self, message:bytes):
        if self.pub_only:
          raise Exception("Can't sign in pub_only !!")
        else:
          return rsa.sign(message,self.privateKey,'SHA-512')
    def verify( self,message:bytes, signature:bytes):
        return rsa.verify(message,signature,self.publicKey)

    def sign_file( self, filename:str):
        if self.pub_only:
          raise Exception("Can't sign in pub_only !!")
        else:
          with open(filename,"rb") as f:
            message=rsa.compute_hash(f,'SHA-512')
            return rsa.sign_hash(message,self.privateKey,'SHA-512')
    def verify_file( self,filename:str, signature:bytes):
        with open(filename,"rb") as f:
          return rsa.verify(f,signature,self.publicKey)

    def find_signature_hash( self, signature:bytes):
        return rsa.find_signature_hash(signature,self.publicKey)

def cksum(filename:str, binary:bin = False, algo:str = "sha512"):
    def file_as_blockiter(afile, blocksize=65536):
       with afile:
          block = afile.read(blocksize)
          while len(block) > 0:
             yield block
             block = afile.read(blocksize)
    mif = getattr(hashlib, algo)
    hasher = mif()
    for block in file_as_blockiter(open(filename,'rb')):
        hasher.update(block)
    return hasher.digest() if binary else hasher.hexdigest()


def sendmsg( sender:str, to:str, message:str):
  # message must be smaller than key size
  # Encrypt mess to with pub
  m=crypto(to, pub_only=True).encrypt(message).encode()
  # Sign crypted message from sender with private
  s=crypto(sender).sign(m)
  return [m,s]

def receivemsg(sender:str, to:str, message:bytes, sign:bytes):
  # message must be smaller than key size
  # Verif Sign sender with pub
  try:
    s=crypto(sender, pub_only=True).verify(message,sign)
  except rsa.pkcs1.VerificationError as e:
    print(f"Error: {e}")
    return False
  # decrypt message for to with private
  return crypto(to).decrypt(m)

if __name__ == '__main__':
  a=logging.getLogger()
  a.setLevel(logging.INFO)

  filename="data3.enc"
  #crypto()
  """
  # Aff hexa sha512 du fichier test
  print(cksum(filename))
  # Aff same from module rsa
  with open(filename,"rb") as f: rsa.compute_hash(f,'SHA-512').hex()
  # Same in binary
  print(cksum(filename,True))
  with open(filename,"rb") as f: rsa.compute_hash(f,'SHA-512')
  """
  # Je suis d'abord u2
  m,s = sendmsg('u2','u1','vi or emacs ?')
  logging.info(f"Mess={m}\nSign={s}")
  # je suis maintenant u1
  logging.info(receivemsg('u2','u1', m, s))
  quit()

  # Signe le fichier test avec u1
  s=u1.sign_file(filename)
  # aff le signature
  print(s.hex())
  #print(u2.find_signature_hash(s))
  ## verify signature with publickey de u1
  print(u1.verify_file(filename,s))




