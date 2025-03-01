import subprocess,base64,tempfile

def encrypt(mikey:str,message:str,key_is_cert:bool = False) -> (str,str):
      result=None
      message_c = message.replace('\r','').replace("'","'\\''")
      cmd = f"echo -n '{message_c}' | openssl pkeyutl -encrypt -pubin -inkey {mikey}"
      if key_is_cert:
        cmd = f"{cmd} -certin"
      ret = subprocess.run( cmd , shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
      if ret.returncode == 0:
        x = base64.b64encode(ret.stdout).decode()
        affsize=70
        result = '\n'.join([x[i:i + affsize] for i in range(0, len(x), affsize)])
      else:
        result = ret.stdout.decode(errors='ignore')
      return (result,cmd)

def decrypt(mikey:str,message:str) -> (str,str):
      message_c = message.replace('\r','')
      cmd = f"openssl pkeyutl -decrypt -inkey {mikey}"
      with tempfile.NamedTemporaryFile() as fp:
          fp.write(message_c.encode())
          fp.flush()
          cmd = f"base64 -d {fp.name} | {cmd}"
          ret = subprocess.run(cmd, shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
          result = ret.stdout.decode(errors='ignore')
      return (result,cmd)

def sign(mikey:str,message:str) -> (str,str):
      message_c = message.replace('\r','').replace("'","'\\''")
      cmd = f"echo -n '{message_c}' | openssl dgst -sha512 -binary | openssl pkeyutl -sign -inkey {mikey}"
      ret = subprocess.run( cmd , shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
      if ret.returncode == 0:
        x = base64.b64encode(ret.stdout).decode()
        affsize=70
        result = '\n'.join([x[i:i + affsize] for i in range(0, len(x), affsize)])
      else:
        result = ret.stdout.decode(errors='ignore')
      return (result,cmd)

def verify(mikey:str,message:str,verifmess:str,key_is_cert:bool = False) -> (str,str):
      message_c = message.replace('\r','')
      cmd = f"echo -n '{message_c}' | openssl dgst -sha512 -binary | openssl pkeyutl -verify -pubin -inkey {mikey}"
      if key_is_cert:
        cmd = f"{cmd} -certin"
      result=None
      data=None
      try:
         data=base64.b64decode(verifmess)
      except Exception as e:
         result = f"Decode base64 error: {e}"
      if result is None:
         with tempfile.NamedTemporaryFile() as fp:
            fp.write(data)
            fp.flush()
            cmd = f"{cmd} -sigfile {fp.name}"
            ret = subprocess.run( cmd , shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
            result = ret.stdout.decode(errors='ignore')
      return (result,cmd)

