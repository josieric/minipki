#! /bin/env python

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import hashes
import datetime
import os,sys,getopt

class cacert:
   NORMAL="\x1b[0m"
   BLUE="\x1b[1;96m"
   RED="\x1b[1;31m"
   GREEN="\x1b[1;32m"

   def __init__(self,file_path:str):
      self.file_path=file_path
      self.loadPEM()

   def loadPEM(self):
     self.certs=[]
     self.ident={}
     # Ouvrir et lire le fichier
     try:
       with open(self.file_path, 'rb') as file:
           cert_data = file.read()
           # Charger les certificats PEM
           self.certs=x509.load_pem_x509_certificates(cert_data)
           i = 0
           for cert in self.certs:
              if cert.signature in self.ident:
                  print(f"{self.RED}Duplicate detected when load{self.NORMAL} {self.file_path} {self.ident[cert.signature]} {i} {cert.subject.rfc4514_string()}")
              self.ident[cert.signature] = i
              i += 1
     except FileNotFoundError:
       print(f"Le fichier {file_path} n'a pas été trouvé.")
     except IOError:
       print(f"Une erreur s'est produite lors de la lecture du fichier {file_path}.")
     except x509.InvalidVersion:
       print("Fichier x509: version invalide.")

   # Fonction pour extraire un attribut des chain CN=,OU=,O= pour les Label
   # ou une valeur par défaut si l'attribut n'existe pas
   @staticmethod
   def get_attribute(oid, attributes, default=""):
       attr = attributes.get_attributes_for_oid(oid)
       return attr[0].value if attr else default

   def displayPEM(self, stdout:bool = True, nokey:bool = True) -> str:
      stdoutstr=""
      nb = 0
      now = datetime.datetime.now(tz=datetime.timezone.utc)
      for cert in self.certs:
         sign=cert.signature
         issuer = cert.issuer.rfc4514_string()
         subject = cert.subject.rfc4514_string()
         not_before = getattr(cert, 'not_valid_before_utc',None) or cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
         not_after = getattr(cert, 'not_valid_after_utc',None) or cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
         label_cn = self.get_attribute(x509.NameOID.COMMON_NAME, cert.subject)
         label_o  = self.get_attribute(x509.NameOID.ORGANIZATION_NAME, cert.subject)
         label_ou = self.get_attribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, cert.subject)
         label = label_cn or label_o or label_ou or subject
         serial = cert.serial_number
         md5_fingerprint = cert.fingerprint(hashes.MD5()).hex()
         sha1_fingerprint = cert.fingerprint(hashes.SHA1()).hex()
         sha256_fingerprint = cert.fingerprint(hashes.SHA256()).hex()

         if self.ident[sign] != nb:
            print(f"{self.RED}Exclude Duplicate{self.NORMAL} {self.file_path} {subject}")
         elif not_after < now:
            print(f"{self.RED}Exclude Expired{self.NORMAL} {self.file_path} not_after:{not_after} {subject}")
         else:
            stdoutstr += f"# Issuer: {issuer}\n"
            stdoutstr += f"# Subject: {subject}\n"
            stdoutstr += f"# Label: {label}\n"
            stdoutstr += f"# Serial: {serial}\n"
            stdoutstr += f"# NotBefore: {not_before}\n"
            stdoutstr += f"# NotAfter: {not_after}\n"
            stdoutstr += f"# MD5 Fingerprint: {':'.join(md5_fingerprint[i:i+2] for i in range(0, len(md5_fingerprint), 2))}\n"
            stdoutstr += f"# SHA1 Fingerprint: {':'.join(sha1_fingerprint[i:i+2] for i in range(0, len(sha1_fingerprint), 2))}\n"
            stdoutstr += f"# SHA256 Fingerprint: {':'.join(sha256_fingerprint[i:i+2] for i in range(0, len(sha256_fingerprint), 2))}\n"
            if not nokey:
              stdoutstr += cert.public_bytes(Encoding.PEM).decode()
            else:
              stdoutstr += "#\n"
         nb += 1

      if stdout:
        print(stdoutstr)
      return stdoutstr

   def savePEM(self, filename:str = None):
      if filename is None:
        filename = self.file_path
      with open(filename, 'w') as output_file:
         output_file.write(self.displayPEM(stdout=False,nokey=False))

   def isincluded(self,ca):
      founded=[]
      mess=""
      for idcrt in ca.ident.keys():
         if idcrt not in self.ident.keys():
           founded.append(False)
           cc = ca.certs[ca.ident[idcrt]]
           mess += f"\t{self.BLUE}not found:{self.NORMAL} {cc.subject.rfc4514_string()}\n"
         else:
           founded.append(True)
      if False in founded:
        print(f"{self.file_path} => {self.RED}KO{self.NORMAL}\n{mess}")
        return False
      else:
        print(f"{self.file_path} => {self.GREEN}OK{self.NORMAL}\n{mess}")
        return True

   def add(self,ca):
      i = len(self.certs)
      for c in ca.certs:
         self.certs.append(c)
         self.ident[c.signature] = i
         i += 1
      self.savePEM()

#####################################################################################
# find /opt/mamba/ -name "cacert*" | xargs ./read_cacert.py /opt/mamba/ed._cacert.pem
#####################################################################################
## Main
if __name__ == '__main__':
   option=["check","display","savefile=","isin=","add="]
   def usage():
     print(f"Syntaxe: {cacert.BLUE}{sys.argv[0]} <options> <PEMfile1> .. <PEMfileN>{cacert.NORMAL}")
     print("\tPermet ajout, affichage, sauvegarde de fichier PEM contenant des certificats publics (Ex: cacert.pem)\n")
     print("Les options sont executées dans l'ordre de la ligne de copmmande\n")
     print(f"{sys.argv[0]} {cacert.BLUE}--check{cacert.NORMAL} <PEMfile1> .. <PEMfileN>\n\tJuste charge le fichier et affiche de potentiels problemes")
     print(f"{sys.argv[0]} {cacert.BLUE}--display{cacert.NORMAL} <PEMfile1> .. <PEMfileN>\n\tAffiche les info de chaque certificats sur la sortie standard")
     print(f"{sys.argv[0]} {cacert.BLUE}--isin=<fileref>{cacert.NORMAL} <PEMfile1> .. <PEMfileN>\n\tVerifie que les certificats de <fileref> sont bien dans les fichiers PEM")
     print(f"{sys.argv[0]} {cacert.BLUE}--savefile=<save>{cacert.NORMAL} <PEMfile1> .. <PEMfileN>\n\tSauvegarde le resultat chargé dans un fichier PEM nommé <save>")
     print("\tSur lui même si --savefile= (cad sans nom de fichier)\n\tLa sauvegarde dédoublonne.")
     print("Exemple:")
     print("\tAfficher les certificats de /opt/mamba/ed._cacert.pem")
     print(f"\t{sys.argv[0]} --display /opt/mamba/ed._cacert.pem")
     print("\tSauvegarder les certificats de /opt/mamba/ed._cacert.pem dans /tmp/save.pem")
     print(f"\t{sys.argv[0]} --savefile=/tmp/save.pem /opt/mamba/ed._cacert.pem")
     print("\tDédoublonner (re-écrit) les certificats de /opt/mamba/ed._cacert.pem")
     print(f"\t{sys.argv[0]} --savefile= /opt/mamba/ed._cacert.pem")
     print("\tVerifier que les certificats de /opt/mamba/ed._cacert.pem sont dans tous les fichiers cacert* trouvés dans /opt/mamba")
     print(f"\tfind /opt/mamba/ -name \"cacert*\" | xargs {sys.argv[0]} --isin=/opt/mamba/ed._cacert.pem")
     print("\tAjouter les certificats de /opt/mamba/ed._cacert.pem à tous les fichiers cacert* trouvés dans /opt/mamba")
     print(f"\tfind /opt/mamba/ -name \"cacert*\" | xargs {sys.argv[0]} --add=/opt/mamba/ed._cacert.pem")
     exit()

   if len(sys.argv) == 0:
      usage()
   try:
       opts, params = getopt.gnu_getopt(sys.argv[1:],"",option)
       ## print(f"{opts} {params}");
   except getopt.GetoptError as e:
       print(f"{cacert.RED}{e}{cacert.NORMAL}")
       usage()
   if len(params) == 0:
       print(f"{cacert.RED}no args file !!{cacert.NORMAL}")
       usage()
   action = {}
   for o, v in opts:
        action[o[2:]] = v
        print(f"{o[2:]} '{v}'")

   for file in params:
     if not os.path.isfile(file):
        print(f"{cacert.RED}File {file} not exists !!{cacert.NORMAL}")
     else:
        print(f"{cacert.BLUE}==> {file}:{cacert.NORMAL}")
        trusted = cacert(file)
        for todo in action.keys():
          if todo == "display":
            trusted.displayPEM(stdout=True,nokey=True)
          elif todo == "check":
            trusted.displayPEM(stdout=False)
          elif todo == "isin":
            caref=cacert(action['isin'])
            trusted.isincluded(caref)
          elif todo == "savefile":
            if action['savefile'] != "":
               trusted.savePEM(filename=action['savefile'])
            else:
               trusted.savePEM()
          elif todo == "add":
            caadd=cacert(action['add'])
            trusted.add(caadd)

