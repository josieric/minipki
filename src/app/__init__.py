#! /usr/bin/env python

from flask import Flask, request, send_from_directory, render_template, Response, g, make_response, url_for, redirect
import logging, os, subprocess, re
#from datetime import datetime
from .dump_certs import getall_cert, read_cert, crlinfos, list_ca
from .crypt_sign import encrypt, decrypt, sign, verify

app = Flask(__name__)
app.logger = logging.getLogger()
app.logger.handlers = logging.getLogger('gunicorn.error').handlers
app.logger.setLevel(logging.DEBUG)

def ges_cookies(req) -> tuple:
    color = req.args.get('color')
    colors=[]
    if color is None:
       color = req.cookies.get('color','green')
    else:
       lf = [ f for f in os.listdir('app/static/color') ]
       lf.sort()
       colors={os.path.splitext(os.path.basename(f)):f for f in lf }
    CADIR=req.cookies.get('CADIR',None)
    return (CADIR,color,colors)

def execcmd(micmd:str,intext:bool=True,location:str = "list"):
    if intext:
      ret = subprocess.run(micmd, stderr=subprocess.STDOUT, shell=True, stdout=subprocess.PIPE, text=intext)
      if ret.returncode == 0:
        info="action OK"
        status=302
      else:
        info="action KO"
        status=200
      # delete shell colors
      stdout_nocolor = re.sub('\x1b\[[0-9;]*m','',ret.stdout)
      miresponse = make_response(f"{info}\n{stdout_nocolor}",status)
      miresponse.headers['Content-Type'] = 'text/plain'
      miresponse.headers['location'] = url_for(location)
      return miresponse
    else:
      ret = subprocess.run(micmd, shell=True, text=intext)
      miresponse = make_response(ret.stdout)
      miresponse.headers['Content-Type'] = 'binary/unknowned'
      return miresponse


@app.route('/intro', methods=['GET','POST'])
def intro():
    CADIR,color,colors = ges_cookies(request)
    infos=""
    res = make_response( render_template("intro.html", caname=CADIR, infos=infos, color=color,colors=colors) )
    res.set_cookie('color',color)
    return res


@app.route('/setCA', methods=['GET','POST'])
def setCA():
    CADIR,color,colors = ges_cookies(request)
    pCADIR=request.form.get('CADIR')
    existing_ca = list_ca()
    if pCADIR is None:
      infos=""
      return make_response( render_template("setCA.html", caname=CADIR, auths=existing_ca, infos=infos, color=color,colors=colors) )
    else:
      if os.path.islink(pCADIR) or os.path.isdir(pCADIR):
        if os.path.isfile(f"{pCADIR}/ca.crt"):
          infos=f"You set authorithy name to '{pCADIR}'"
          res = make_response( render_template("setCA.html", caname=CADIR, auths=existing_ca, infos=infos, color=color,colors=colors) ,302)
          res.set_cookie('CADIR',pCADIR)
          res.headers['location']=url_for("list")
          app.logger.debug(f"Location = {res.headers['location']}")
          return res
        else:
          infos=f"'{pCADIR}' is not an authorithy directory !!"
          return make_response( render_template("setCA.html", caname=CADIR, auths=existing_ca, infos=infos, color=color,colors=colors) )
      else:
        infos=f"authorithy name '{pCADIR}' not exists !!"
        return make_response( render_template("setCA.html", caname=CADIR, auths=existing_ca, infos=infos, color=color,colors=colors) )

@app.route('/', methods=['GET','POST'])
def list():
    CADIR,color,colors = ges_cookies(request)
    if CADIR is None or not os.path.isfile(f"{CADIR}/ca.crt"):
      return redirect(url_for("setCA"))
    infos = ""
    tabfile=getall_cert(CADIR).items()
    res = make_response( render_template("list.html",caname=CADIR ,tabfile=tabfile, infos=infos, color=color,colors=colors) )
    res.set_cookie('color',color)
    return res

@app.route('/download', methods=['POST'])
def download():
   CADIR,color,colors = ges_cookies(request)
   mifile=f"{CADIR}/{request.form.get('file')}"
   fileext=mifile[-4:]
   if os.path.isfile(mifile) and fileext in ('.crt','.key','.crl','.pem'):
     cname=request.form.get('cname')
     newfile=f"{cname}{fileext}"
     mime = "application/x-pem-file"
     with open(mifile,'rb') as fh:
       return Response(fh.read(), mimetype=mime,headers={"Content-disposition": f'attachment; filename="{newfile}"'}, direct_passthrough=True)
   else:
     return Response(f"<h4>404 File Not found</h4>File: {mifile} not exists in CA '{CADIR}'" , status=404)

@app.route('/info', methods=['GET'])
def info():
   CADIR,color,colors = ges_cookies(request)
   infos = ""
   pfile=request.args.get('file')
   mifile=f"{CADIR}/{pfile}"
   cname=os.path.basename(os.path.dirname(pfile))
   if os.path.islink(mifile):
     crtdata = read_cert(mifile)
   elif os.path.exists(mifile):
     if os.path.basename(pfile) == 'ca.crt':
       cname="Certificate Authority"
       crtdata = read_cert(mifile)
     else:
       crtdata = read_cert(mifile,revoked='R')
   else:
     return redirect(url_for("list"))
   res = make_response( render_template("info.html",caname=CADIR , fname=pfile, cname=cname, crtdata=crtdata, infos=infos, color=color,colors=colors) )
   res.set_cookie('color',color)
   return res

@app.route('/createCA', methods=['GET','POST'])
def createCA():
    CADIR,color,colors = ges_cookies(request)
    infos = ""
    caname = request.form.get('caname')
    if caname is not None and caname != '':
      caname=caname.replace(" ",".")
      suffixdn = request.form.get('suffixdn')
      fqdn_crl = request.form.get('fqdn_crl')
      port_crl = request.form.get('port_crl')
      res = execcmd( f"./create_ca '{caname}' '{suffixdn}' '{fqdn_crl}' '{port_crl}'" , location="list" )
      res.set_cookie('CADIR',caname)
      return res
    res = make_response( render_template("createCA.html", caname=caname, infos=infos, color=color,colors=colors ))
    res.set_cookie('color',color)
    return res

@app.route('/create', methods=['GET','POST'])
def create():
    CADIR,color,colors = ges_cookies(request)
    infos = ""
    ctype = request.form.get('ctype')
    if ctype not in ('client','server'):
      ctype = 'client'
    res = make_response( render_template("create.html" ,caname=CADIR, ctype=ctype, infos=infos, color=color,colors=colors ))
    res.set_cookie('color',color)
    return res

@app.route('/create/client/<name>', methods=['POST'])
def create_client(name:str = None):
    if name is not None:
      os.environ["ACNAME"] = request.cookies.get('CADIR')
      return execcmd( f"./create_client '{name}'" )
    else:
      miresponse = make_response("client name is not defined !!")
      miresponse.headers['Content-Type'] = 'text/plain'
      return miresponse

@app.route('/create/server/<name>', methods=['POST'])
def create_server(name:str = None):
    if name is not None:
      os.environ["ACNAME"] = request.cookies.get('CADIR')
      return execcmd( f"./create_server '{name}'" )
    else:
      miresponse = make_response("server name is not defined !!")
      miresponse.headers['Content-Type'] = 'text/plain'
      return miresponse

@app.route('/revoke/<name>', methods=['POST'])
def revoke(name:str = None):
    if name is not None:
      os.environ["ACNAME"] = request.cookies.get('CADIR')
      return execcmd( f"./revoke '{name}' && ./create_crl" )
    else:
      miresponse = make_response("name is not defined !!")
      miresponse.headers['Content-Type'] = 'text/plain'
      return miresponse

@app.route('/pkcs12', methods=['GET','POST'])
def pkcs12():
   cname = request.form.get('cname',None)
   ctype = request.form.get('ctype',None)
   if cname is not None:
     pkcs12p = request.form.get('pkcs12p',"")
     if pkcs12p != "":
        os.environ["ACNAME"] = request.cookies.get('CADIR')
        with subprocess.Popen( ["./create_pkcs12",cname, pkcs12p] , stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE) as ret:
          return Response(ret.stdout.read(), mimetype='application/x-pkcs12',headers={"Content-disposition": f'attachment; filename="{cname}.pfx"'}, direct_passthrough=True)
     else:
      CADIR,color,colors = ges_cookies(request)
      infos = ""
      res = make_response( render_template("pkcs12.html" ,caname=CADIR, cname=cname, ctype=ctype, infos=infos, color=color,colors=colors ))
      res.set_cookie('color',color)
      return res
   else:
    return redirect(url_for("list"))

@app.route('/newcrl', methods=['POST'])
def newcrl():
   os.environ["ACNAME"] = request.cookies.get('CADIR')
   return execcmd( f"./create_crl" , location="crl")

@app.route('/crl', methods=['GET','POST'])
def crl():
   CADIR,color,colors = ges_cookies(request)
   infos = ""
   mifile=f"{CADIR}/ca.crl"
   cname="CRL"
   if os.path.isfile(mifile):
     crldata=crlinfos(mifile)
   else:
     crldata=["-1","Not Found",[]]
   app.logger.debug(f"crldata={crldata}")
   res = make_response( render_template("info.html",caname=CADIR , fname='ca.crl', cname=cname, crtdata=crldata, infos=infos, color=color,colors=colors) )
   res.set_cookie('color',color)
   return res

@app.route('/message', methods=['GET','POST'])
def mess():
   CADIR,color,colors = ges_cookies(request)
   infos = ""
   result=""
   ctype  = request.form.get('ctype')
   cname  = request.form.get('cname')
   if ctype is None or cname is None:
      return redirect(url_for("list"))

   pubs = [ f'{ctype}.crt', 'rsa_pkcs1.pub', 'rsa.pub' ]
   privs = [ f'{ctype}.key', 'rsa_pkcs1' ]
   message  = request.form.get('message','')
   verifmess = request.form.get('verifmess','')
   mtype  = request.form.get('mtype')
   key  = request.form.get('key','')
   mikey = f"{CADIR}/{ctype}/{cname}/{key}"
   app.logger.debug(f"key2use: {mikey}")
   cmd=""
   if mtype == "encrypt":
      infos=f"Encrypt with public {os.path.basename(mikey)}"
      if key == f'{ctype}.crt':
        Iscert=True
      else:
        Iscert=False
      result,cmd = encrypt(mikey,message,Iscert)
   elif mtype == "decrypt":
      infos=f"Decrypt with private {os.path.basename(mikey)}"
      result,cmd = decrypt(mikey,message)
   elif mtype == "sign":
      infos=f"Sign with private {os.path.basename(mikey)}"
      result,cmd = sign(mikey,message)
   elif mtype == "verify":
      infos=f"Verify with public {os.path.basename(mikey)}"
      if key == f'{ctype}.crt':
        Iscert=True
      else:
        Iscert=False
      result,cmd = verify(mikey,message,verifmess,Iscert)
   res = make_response( render_template("mess.html",caname=CADIR , ctype=ctype, cname=cname, message=message, keyused=key,
                                                    mtype=mtype, verifmess=verifmess, pubs=pubs, privs=privs, addinfo=infos,
                                                    result=result, infos=cmd, color=color,colors=colors) )
   res.set_cookie('color',color)
   return res

@app.route('/mess_to', methods=['GET','POST'])
def mess_to():
   # Simulation envoi d'un message
   # ctype/cname is sender
   ctype  = request.form.get('ctype')
   cname  = request.form.get('cname')
   if ctype is None or cname is None:
      return redirect(url_for("list"))
   theother  = request.form.get('theother')
   CADIR,color,colors = ges_cookies(request)
   infos,addinfo = ("",'')
   allcerts=[]
   for f,v in getall_cert(CADIR).items():
      cn2=os.path.dirname(f)
      ct2=os.path.basename(os.path.dirname(cn2))
      cn2=os.path.basename(cn2)
      if cn2 != CADIR and cn2 != cname:
        allcerts.append(f"{ct2} {cn2}")
   message  = request.form.get('message','')
   signature  = request.form.get('signature','')
   res_sign,res_enc = ('','')
   if theother is not None:
      ctype2,cname2  = theother.split(' ')
      # Must sign with sender private and encrypt with receiver public
      sender_key = f"{CADIR}/{ctype}/{cname}/{ctype}.key"
      receiver_pub = f"{CADIR}/{ctype2}/{cname2}/{ctype2}.crt"
      app.logger.debug(f"pub={receiver_pub}\nkey={sender_key}")
      res_sign,cmd_sign = sign(sender_key,message)
      res_enc,cmd_enc   = encrypt(receiver_pub,message,True)
   res = make_response( render_template("mess_to.html",caname=CADIR , ctype=ctype, cname=cname, message=message, signature=signature,
                                                    theother=theother, allcerts=allcerts,
                                                    res_sign=res_sign, res_enc=res_enc, infos=infos, color=color,colors=colors) )
   res.set_cookie('color',color)
   return res


@app.route('/mess_from', methods=['GET','POST'])
def mess_from():
   # Simulation reception d'un message
   # ctype/cname is receiver
   ctype  = request.form.get('ctype')
   cname  = request.form.get('cname')
   if ctype is None or cname is None:
      return redirect(url_for("list"))
   theother = request.form.get('theother')
   CADIR,color,colors = ges_cookies(request)
   infos,addinfo = ("",'')
   allcerts=[]
   for f,v in getall_cert(CADIR).items():
      cn2=os.path.dirname(f)
      ct2=os.path.basename(os.path.dirname(cn2))
      cn2=os.path.basename(cn2)
      if cn2 != CADIR and cn2 != cname:
        allcerts.append(f"{ct2} {cn2}")
   message  = request.form.get('message','')
   signature  = request.form.get('signature','')
   res_verif,res_dec = ('','')
   if theother is not None:
     ctype2,cname2  = theother.split(' ')
     # Must Verify with sender public and encrypt with receiver private
     sender_pub = f"{CADIR}/{ctype2}/{cname2}/{ctype2}.crt"
     receiver_key = f"{CADIR}/{ctype}/{cname}/{ctype}.key"
     app.logger.debug(f"pub={sender_pub}\nkey={receiver_key}")
     res_dec,cmd_dec = decrypt(receiver_key,message)
     res_verif,cmd_verif = verify(sender_pub,res_dec,signature,True)
   res = make_response( render_template("mess_from.html",caname=CADIR , ctype=ctype, cname=cname, message=message, signature=signature,
                                                    theother=theother, allcerts=allcerts,
                                                    res_verif=res_verif, res_dec=res_dec, infos=infos, color=color,colors=colors) )
   res.set_cookie('color',color)
   return res

@app.route('/favicon.ico')
def favicon():
    return send_from_directory("./static",'favicon.ico', mimetype='image/icon')

if __name__ == '__main__':
    app.run(host="0.0.0.0")

