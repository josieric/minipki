#! /usr/bin/env python

import os,subprocess,io
from threading import Thread
import pickle,gzip
import time

class crypto:
    def __init__(self, key:str):
      self.cmdtab=["openssl","enc","-aes-256-cbc","-pbkdf2","-salt"]
      if os.path.isfile(key):
        self.cmdtab.append("-kfile")
      else:
        self.cmdtab.append("-k")
      self.cmdtab.append(key)
    def print_cmd(self):
      print('\t'+' '.join(self.cmdtab))
    def get_cmd(self):
      return ' '.join(self.cmdtab)

    ## Genere data for test
    @staticmethod
    def get_data(nbl:int=100000,nbs:int=128):
       import string,random
       data=[]
       dt=time.time()
       for i in range(1,nbl):
         lib1 = ''.join(random.choice(string.printable) for n in range(nbs))
         lib2 = ''.join(random.choice(string.printable) for n in range(nbs))
         data.append([i,chr(i),lib1,lib2])
       print(f"data generated {time.time() - dt}")
       return data

    ## Simple function SaveObject & RestoreObject (with pickle & gzip)
    @staticmethod
    def loadmsg(data):
       return pickle.loads(gzip.decompress(data))
    @staticmethod
    def dumpmsg(data):
       return gzip.compress(pickle.dumps(data, 4))

    @staticmethod
    def genere_key(size:int=256):
      return subprocess.run(f'openssl rand -base64 {size} | tr -d "\n"', stderr=subprocess.STDOUT, shell=True, stdout=subprocess.PIPE, text=True).stdout
    @staticmethod
    def write_key(keyfile:str, size:int=256):
      dt=time.time()
      return subprocess.run(f'openssl rand -writerand {keyfile} {size}', stderr=subprocess.STDOUT, shell=True, stdout=subprocess.PIPE).returncode

    @staticmethod
    def writein_thread(proc,inputs):
       def _write_stdin(proc,inputs):
           try:
             proc.stdin.write(inputs)
           except IOError as e:
             print(f"Error during write stdin: {e}")
           proc.stdin.close()
       tin = Thread(target=_write_stdin, args=(proc, inputs))
       tin.start()
       return tin

class scrypt(crypto):
    def decryptload(self,filename):
      self.cmdtab.append("-d")
      #self.print_cmd()
      with open(filename,"rb") as fh:
           with subprocess.Popen(self.cmdtab, stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE) as ret:
              self.cmdtab = self.cmdtab[:-1]
              t=self.writein_thread(ret,fh.read())
              return self.loadmsg(ret.stdout.read())

    def encryptdump(self,data,filename):
      self.cmdtab.append("-e")
      #self.print_cmd()
      with open(filename,"wb") as fh:
         with subprocess.Popen(self.cmdtab, stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE) as ret:
            self.cmdtab = self.cmdtab[:-1]
            t=self.writein_thread(ret,self.dumpmsg(data))
            fh.write(ret.stdout.read())
            return True

class scrypt0(crypto):
    def encryptdump(self,data,filename):
      ret = subprocess.run(f"{self.get_cmd()} -e", input=self.dumpmsg(data), stderr=subprocess.STDOUT, shell=True, stdout=subprocess.PIPE)
      if ret.returncode == 0:
        with open(filename,"wb") as fh:
          fh.write(ret.stdout)
          return True
      else:
        raise Exception(f"Error: {ret}")

    def decryptload(self,filename):
      with open(filename,"rb") as fh:
        ret = subprocess.run(f"{self.get_cmd()} -d", input=fh.read(), stderr=subprocess.STDOUT, shell=True, stdout=subprocess.PIPE)
        if ret.returncode != 0:
          raise Exception(f"Error: {ret}")
      return self.loadmsg(ret.stdout)

if __name__ == "__main__":
  # Load some json data
  #import json
  #with open("stations_meteo.json") as f:
  #  data=json.load(f)
  # random data
  data=crypto.get_data()
  key="my.key"
  scrypt.write_key(key)
  keys=['MonS3cret-Que-N0B0dy-2@1T', scrypt.genere_key(), None ]
  nb=0
  for key in keys:
     nb = nb+1
     if key is None:
       key = "my.key"
     a=scrypt0(key)
     filename=f'data{nb}.enc'
     print(f"\n{filename} - KEY={key}")
      
     dt=time.time()
     if a.encryptdump(data,filename):
       print(f"encrypt and write in file {filename} {time.time() - dt}")
     else:
       print("Pas beau !!")

     dt=time.time()
     s=a.decryptload(filename)
     print(f"decrypt from file {filename} {time.time() - dt}")

     
     #print(f"{len(s)}\n{s['features'][nb]}")
     print(f"{type(s)} {len(s)}")
  
