#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import os,sys
import base64
import logging
import argparse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import UnsupportedAlgorithm

class crypto:
    algo = hashes.SHA512()
    mgf = padding.MGF1(algorithm=algo)
    crypt_padding = padding.OAEP( mgf=mgf, algorithm=algo, label=None)
    verif_padding = padding.PSS( mgf=mgf, salt_length=padding.PSS.MAX_LENGTH)

    def __init__(self, dirname: str = f"{os.environ['HOME']}/.ssh", fn_pub: str = "id_rsa.pub", fn_key: str = "id_rsa", pub_only: bool = False, size: int = 4096):
        self.pub_only = pub_only
        self.dirname = dirname
        self._create_size = size
        if not os.path.isdir(dirname):
            dirname = os.path.join(os.path.dirname(__file__), dirname)
            os.mkdir(dirname)
        keyfile = os.path.join(dirname, fn_key) if not pub_only else None
        pubfile = os.path.join(dirname, fn_pub)
        self._load_keys(keyfile,pubfile)

    def _load_keys(self,keyfile:str,pubfile):
        if self.pub_only:
            if os.path.isfile(pubfile):
               logging.info(f"Load {self.dirname} public:{pubfile}")
               with open(pubfile, "rb") as f:
                   #self.publicKey = serialization.load_ssh_public_key(f.read(), backend=default_backend())
                   self.publicKey = self.load_public(f.read())
            else:
               raise Exception("Can't generate public key only !!")
        else: # not pub_only
            force_create_pub = False
            if os.path.isfile(keyfile):
              logging.info(f"Load {self.dirname} private:{keyfile}")
              with open(keyfile, "rb") as f:
                self.privateKey = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
            else: # no keyfile and not pub_only == generate a key file
                logging.info(f"Create {self.dirname} private:{keyfile}")
                self.privateKey = rsa.generate_private_key(public_exponent=65537, key_size=self._create_size, backend=default_backend())
                with open(keyfile, "wb") as f:
                   f.write(self.privateKey.private_bytes( encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption()))
                os.chmod(keyfile, 0o600)
                force_create_pub = True

            if os.path.isfile(pubfile) and not force_create_pub:
              logging.info(f"Load {self.dirname} public:{pubfile}")
              with open(pubfile, "rb") as f:
                self.publicKey = self.load_public(f.read())
            else: # pubfile doesn't exists create it from private key
                logging.info(f"Create {self.dirname} public:{pubfile} force:{force_create_pub}")
                self.publicKey = self.privateKey.public_key()
                with open(pubfile, "wb") as f:
                  f.write(self.publicKey.public_bytes( encoding=serialization.Encoding.OpenSSH, format=serialization.PublicFormat.OpenSSH))

    def encrypt(self, msg:str, b64:bool = True) -> bytes:
        encrypted = self.publicKey.encrypt( msg.encode(), self.crypt_padding )
        return base64.b64encode(encrypted) if b64 else encrypted

    def decrypt(self, enc:str, b64:bool = True) -> str:
        if self.pub_only:
            raise Exception("Can't decrypt in pub_only !!")
        else:
            enc = base64.b64decode(enc) if b64 else enc
            try: 
              decrypted = self.privateKey.decrypt( enc, self.crypt_padding)
              return decrypted.decode()
            except ValueError as e:
              logging.debug(f"Decrypt Error {e}")
              return None

    def sign(self, message:bytes, b64:bool = False) -> bytes:
        if self.pub_only:
            raise Exception("Can't sign in pub_only !!")
        else:
            sgn = self.privateKey.sign( message, self.verif_padding, self.algo)
            if b64:
               return base64.b64encode(sgn)
            else:
               return sgn

    def verify(self, message: bytes, signature: bytes, b64:bool = False) -> bool:
        try:
            if b64:
                signature = base64.b64decode(signature)
            self.publicKey.verify( signature, message, self.verif_padding, self.algo)
            logging.debug(f"Verif True")
            return True
        except Exception as e:
            logging.debug(f"Verif False {e}")
            return False

    def sendmsg(self, topub: str, message: str) -> [bytes, bytes]:
        m = crypto(os.path.dirname(topub), fn_pub=os.path.basename(topub), pub_only=True).encrypt(message, b64=False)
        s = self.sign(m)
        return [base64.b64encode(m), base64.b64encode(s)]

    def receivemsg(self, frompub: str, message: bytes, sign: bytes) -> [bool, bytes]:
        try:
            if not crypto(os.path.dirname(frompub), fn_pub=os.path.basename(frompub), pub_only=True).verify(base64.b64decode(message), base64.b64decode(sign)):
              logging.debug("Verify signature failed")
              return [False, self.decrypt(message)]
        except Exception as e:
            logging.debug(f"Error: {e}")
            return [ False, None ]
        logging.debug("Verified")
        return [ True , self.decrypt(message) ]

    @staticmethod
    def load_public(content:bytes):
       loads = [ serialization.load_pem_public_key , serialization.load_ssh_public_key ]
       public_key = None
       for loader in loads:
           try:
               public_key = loader( content, backend=default_backend()  )
               return public_key
           except (UnsupportedAlgorithm, ValueError):
               pass
       if public_key is None:
           raise Exception("No supportedAlgorithm to read public file")
       return None

    def get_pub_format(self, ktype:str = None):
       # Convertir la clé en différents formats
       formats = { "SubjectPublicKeyInfo": serialization.PublicFormat.SubjectPublicKeyInfo,
               "PKCS1" : serialization.PublicFormat.PKCS1,
               "OpenSSH" : serialization.PublicFormat.OpenSSH }
       def get_pemkey(fmt_name,fmt):
         if fmt_name == "OpenSSH":
           return self.publicKey.public_bytes( encoding=serialization.Encoding.OpenSSH, format=fmt)
         else:
           return self.publicKey.public_bytes( encoding=serialization.Encoding.PEM, format=fmt)

       if ktype is not None and ktype in formats:
           return get_pemkey(ktype, formats[ktype])
       else:
         for fmt_name, fmt in formats.items():
           print(f"{fmt_name}\n{get_pemkey(fmt_name, fmt).decode().strip()}")


def grostest():
    # u1 = ./u1/id_rsa & .pub
    u1 = crypto('u1')
    # u2 = ./test/id_rsa & .pub
    u2 = crypto('u2')
    #u2.get_pub_format()

    # u1 send signed msg to u2
    print()
    m,s = u1.sendmsg('u2/id_rsa.pub','Ola l\'ami')
    #print(f"msg: {m}\nsig: {s}")
    # u2 receive signed msg from u1
    verif,msg = u2.receivemsg('u1/id_rsa.pub',m,s)
    print(f"Verified:{verif} msg:{msg}\n")
    assert verif , "La verif doit etre bonne"
    assert msg=='Ola l\'ami' , "Le message n'est pas le bon"

    # Verif avec ma propre clé bête mais pour les tests
    verif,msg = u2.receivemsg('u2/id_rsa.pub',m,s)
    print(f"Verified:{verif} msg:{msg}\n")
    assert not verif , "La verif doit etre fausse"

    # + decrypt mauvaise clé bête mais pour les tests
    verif,msg = u1.receivemsg('u2/id_rsa.pub',m,s)
    print(f"Verified:{verif} msg:{msg}\n")
    assert not verif , "La verif doit etre fausse"

def __main__():
    parser = argparse.ArgumentParser(description=(
                              "SSH Key Cryptography Tool\n"
                              "\tOption dirname is the 'keystore'\n"
                              "\tOptions keyfile & pubfile are names of private key and public key files\n"
                              "\tIf keyfile is not in keystore => create private & public keys\n"
                              "\tIf keyfile is in keystore AND pubfile is not in keystore => create public key\n"
                  ),
                  formatter_class=argparse.RawTextHelpFormatter)
    # Catégorie "base"
    # Arguments pour les chemins de fichiers et autres paramètres
    base_group = parser.add_argument_group('Keys Parameters')
    base_group.add_argument('--dirname', type=str, default=f'{os.environ["HOME"]}/.ssh', help="Directory for keystore (default: %(default)s).")
    base_group.add_argument('--pubfile', type=str, default='id_rsa.pub', help="Public key file name (default: %(default)s).")
    base_group.add_argument('--keyfile', type=str, default='id_rsa', help="Private key file name (default: %(default)s).")
    base_group.add_argument('--size'   , type=int, default=4096, help="RSA Key size. (default: %(default)s)")
    # Catégorie "action"
    action_group = parser.add_mutually_exclusive_group(required=False)
    # Ajout des arguments pour les fonctionnalités "pub-only"
    action_group.add_argument('--encrypt', metavar='MESSAGE', type=str, help="Encrypt a message with the public key (of the receiver).")
    action_group.add_argument('--verify', metavar=('MESSAGE', 'SIGNATURE'), type=str, nargs=2, help="Verify a signature against a message with the public key (of the sender).")
    # Ajout des arguments pour les fonctionnalités "with keyfile"
    action_group.add_argument('--decrypt', metavar='MESSAGE', type=str, help="Decrypt a message with the private key (of the receiver).")
    action_group.add_argument('--sign', metavar='MESSAGE', type=str, help="Sign a message with the private key (of the sender).")
    # Ajout des arguments pour les fonctionnalités "sending message"
    action_group.add_argument('--send-msg', nargs=2, metavar=('PUBLIC_KEY', 'MESSAGE'), help="Send a signed message to a public key (need public key of receiver).")
    action_group.add_argument('--receive-msg', nargs=3, metavar=('PUBLIC_KEY', 'MESSAGE', 'SIGNATURE'), help="Receive a signed message (need public key of sender).")

    args = parser.parse_args()
    pub_only=False
    if args.encrypt or args.verify:
        pub_only=True

    # Création de l'objet crypto
    crypto_instance = crypto(dirname=args.dirname, fn_pub=args.pubfile, fn_key=args.keyfile, pub_only=pub_only, size=args.size)

    if args.send_msg:
        recipient_pubkey, message = args.send_msg
        encrypted_msg, signature = crypto_instance.sendmsg(recipient_pubkey, message)
        logging.info(f"Encrypted message: {encrypted_msg.decode()}\nMessage signature: {signature.decode()}")
    elif args.receive_msg:
        recipient_pubkey, message, signature = args.receive_msg
        verified, decrypted_msg = crypto_instance.receivemsg(recipient_pubkey, message, signature)
        logging.info(f"Verified: {verified}\nMessage: {decrypted_msg}")

    elif args.encrypt:
        message = args.encrypt
        encrypted_msg = crypto_instance.encrypt(message, b64=True)
        logging.info(f"Encrypt message: {encrypted_msg.decode()}")
    elif args.decrypt:
        message = args.decrypt
        decrypted_msg = crypto_instance.decrypt(message, b64=True)
        logging.info(f"Decrypt message: {decrypted_msg}")

    elif args.verify:
        message, signature = args.verify
        verified = crypto_instance.verify(message.encode(), signature, b64=True)
        logging.info(f"Verified: {verified}")
    elif args.sign:
        message = args.sign
        sign_msg = crypto_instance.sign(message.encode(), b64=True)
        logging.info(f"Signature: {sign_msg.decode()}")

    else:
        crypto_instance.get_pub_format()
        parser.print_help()


if __name__ == '__main__':
    logging.getLogger().setLevel(logging.INFO)

    if len(sys.argv) > 1 and sys.argv[1] == "test":
        grostest()
        exit()
    __main__()

