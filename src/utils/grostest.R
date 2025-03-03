PYTHONBIN<-"/opt/mamba/bin/python"
Sys.setenv("RETICULATE_PYTHON"=PYTHONBIN)
reticulate::use_python(python=PYTHONBIN, require=TRUE)

Sys.setenv("PYTHONPATH"="/home/EJ33AD1N/py_crypt_openssl")

library(reticulate)
pyc <- reticulate::import("SimpleCrypt")

pyc$scrypt$write_key("my.key")

chiffreur=pyc$scrypt("my.key")
chiffreur$encryptdump(r_to_py(iris),"data3.enc")

chiffreur=pyc$scrypt("my.key")
df=chiffreur$decryptload("data3.enc")
df

