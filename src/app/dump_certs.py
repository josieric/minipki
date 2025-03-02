#! /usr/bin/env python3
# -*- coding: utf-8 -*-

from cryptography import x509
from cryptography.hazmat.primitives import hashes

import datetime
import os, json
import sys


def crlinfos(filename:str = 'ca.crl'):
  with open(filename) as fh:
    crl=fh.read()
  crl = x509.load_pem_x509_crl(crl.encode())
  ## crl.get_revoked_certificate_by_serial_number(0xabcdef02)
  certs=[]
  for c in crl:
    certs.append([hex(c.serial_number),c.revocation_date_utc])
  for e in crl.extensions:
    crl_number=None
    if getattr(e.value,'crl_number'):
      crl_number = e.value.crl_number
      break
  return((crl_number, crl.issuer.rfc4514_string(), crl.last_update_utc, crl.next_update_utc, certs))

def read_cert(pemfile, revoked="V"):
  with open(pemfile) as fh:
    cert=fh.read()

  def get_attribute(oid, attributes, default=""):
       attr = attributes.get_attributes_for_oid(oid)
       return attr[0].value if attr else default

  def format_fingerprint(fingerprint):
     return ':'.join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))

  cert = x509.load_pem_x509_certificate(cert.encode())
  now = datetime.datetime.now(tz=datetime.timezone.utc)
  sign=cert.signature
  issuer = cert.issuer.rfc4514_string()
  subject = cert.subject.rfc4514_string()
  not_before = getattr(cert, 'not_valid_before_utc',None) or cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
  not_after = getattr(cert, 'not_valid_after_utc',None) or cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
  dn = cert.subject.rfc4514_string()
  label_cn = get_attribute(x509.NameOID.COMMON_NAME, cert.subject)
  label_o  = get_attribute(x509.NameOID.ORGANIZATION_NAME, cert.subject)
  label_ou = get_attribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, cert.subject)
  label = label_cn or label_o or label_ou or subject
  serial = hex(cert.serial_number)
  md5_fp = format_fingerprint(cert.fingerprint(hashes.MD5()).hex())
  sha1_fp = format_fingerprint(cert.fingerprint(hashes.SHA1()).hex())
  sha256_fp = format_fingerprint(cert.fingerprint(hashes.SHA256()).hex())

  if not_after < now:
      revoked="E"
  extent=[]
  for ext in cert.extensions:
     if isinstance(ext.value, x509.extensions.ExtendedKeyUsage):
       vals = [x._name for x in ext.value or []]
       extent.append(f"{ext.oid._name}: {vals}")
     elif isinstance(ext.value, x509.extensions.CRLDistributionPoints):
       vals = [x for x in ext.value or []]
       extent.append(f"{ext.oid._name}: {vals}")
     elif isinstance(ext.value, x509.extensions.SubjectKeyIdentifier):
       extent.append(f"{ext.oid._name}: {format_fingerprint(ext.value.digest.hex())}")
     elif isinstance(ext.value, x509.extensions.AuthorityKeyIdentifier):
       key_identifier=format_fingerprint(ext.value.key_identifier.hex())
       authority_cert_issuer=None
       authority_cert_serial_number=None
       if ext.value.authority_cert_issuer is not None:
         authority_cert_issuer=format_fingerprint(ext.value.authority_cert_issuer.hex())
       if ext.value.authority_cert_serial_number is not None:
         authority_cert_serial_number=format_fingerprint(ext.value.authority_cert_serial_number.hex())
       extent.append(f"{ext.oid._name}: key_identifier={key_identifier}, authority_cert_issuer={authority_cert_issuer}, authority_cert_serial_number={authority_cert_serial_number}")
     elif isinstance(ext.value, x509.extensions.SubjectAlternativeName):
       extent.append(f"{ext.oid._name} {[x._value for x in ext.value or []]}")
     else:
       extent.append(f"{ext.value}")

  return((serial,dn,label,not_after,not_before,revoked,md5_fp,sha1_fp,sha256_fp,extent))

def list_ca():
   ret = []
   for n in os.listdir("."):
     if os.path.isdir(n):
       if os.path.isfile(f"{n}/ca.crt"):
           ret.append(n)
   return ret

def getall_cert(basedir:str = "cadata"):
  ret = { }
  ret[f"{basedir}/ca.crt"] = read_cert(f"{basedir}/ca.crt")
  if os.path.isdir(basedir):
    for d in ("client","server"):
      dbase = f"{basedir}/{d}"
      for n in os.listdir(dbase):
        fname = dbase+"/"+n+"/"+d+".crt"
        if os.path.isfile(fname):
          ret[fname] = read_cert(fname)
        else:
          # get file.pem in same directory
          fnamepem = [ x for x in filter( lambda x: x[-4:] == '.pem', os.listdir(dbase+"/"+n) ) ]
          if len(fnamepem) > 0:
            fname = dbase+"/"+n+"/"+ fnamepem[0]
            ret[fname] = read_cert(fname, revoked="R")
          else:
            ret[fname] = None
  else:
    print(f"{basedir} is not a directory.")
  return ret

if __name__ == "__main__":
  sep=" "
  if len(sys.argv) > 1:
    certs = getall_cert(sys.argv[1]).items()
  else:
    certs = getall_cert().items()

  for f,v in certs:
    print(f"\n{f}")
    if v is not None:
      for i in v:
        print(f"\t{i}")

