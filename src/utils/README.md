# &#128272; py_crypt_openssl

## &#128712; Principe
Ce module permet le stockage et la lecture d'un objet python (ou R via reticulate).  
Le fichier obtenu est chiffré en AES-256-CBC (avec itération et grain de sel).  
(Cf `openssl enc -aes-256-cbc -pbkdf2 -salt`)  
Ne doit être utilisé QUE avec des données de quelques Go (10 really max !!!)

## &#128208; Dépendances
Ce module utilise :
 - les modules pickle et gzip de python
 - La commande `openssl enc`

## &#128273; Utilisation de Clé/password pour encrypt/decrypt
### Méthode avec un simple mot de passe:
  `chiffreur=scrypt("MonS3cret-Que-N0B0dy-2@1T")`  
  &#128073; le pass est utilisé directement comme clé
### Méthode avec un mot de passe généré (encoding: base64)
  `key=scrypt.genere_key()`  
  `chiffreur=scrypt(key)`  
  &#128073; Un pass est généré (binarysize=256) en base64 pour être utilisé comme "password string"
### Méthode avec une clé stockée dans un fichier (binary file)
  `keyfile="./path/to/my.key"`  
  `scrypt.write_key(keyfile)`  
  `chiffreur=scrypt(keyfile)`  
  &#128073; Clé 'binaire' générée dans le fichier my.key (binarysize=256)  
  &#128073; Clé 'binaire' utilisée par openssl depuis le fichier

## &#127477; Usage en python
### &#128190; Sauvegarde d'un objet en mémoire python dans un fichier chiffré
`data=... ... ...`  
`from SimpleCrypt import scrypt`  
`chiffreur=scrypt("./path/to/my.key")`  
`df=chiffreur.encryptdump(data,"data3.enc")`

### &#128220; Chargement d'un objet python depuis un fichier chiffré
`from SimpleCrypt import scrypt`  
`chiffreur=scrypt("./path/to/my.key")`  
`df=chiffreur.decryptload("data3.enc")`

## &#127479; Usage en R
### Chargement de reticulate et du module SimpleCrypt
`Sys.setenv("PYTHONPATH"="/path/to/directory/py_crypt_openssl")`  
`library(reticulate)`  
`pyc <- reticulate::import("SimpleCrypt")`  

### &#128273; Création d'une clé dans le fichier my.key
`pyc$scrypt$write_key("my.key")`

### &#128190; Sauvegarde d'un objet en mémoire R dans un fichier chiffré
`chiffreur=pyc$scrypt("my.key")`
`chiffreur$encryptdump(r_to_py(iris),"data3.enc")`

### &#128220; Chargement d'un objet R depuis un fichier chiffré
`chiffreur=pyc$scrypt("my.key")`  
`df=chiffreur$decryptload("data3.enc")`

