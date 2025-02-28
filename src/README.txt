######################################################################################
## Créer des authorités et générer des certificats clients et serveurs
## Cad Mini PKI avec opérations minimales
###### MISE EN GARDE ######
## Cette façon de faire est MINIMALE
## Il s'agit de la "marche" juste après (ou pas loin) du certificat auto-signé simple.
## Les politiques de passphrase, de jours de validité, de rythme de la CRL, le délai 
## de validité des certificats, les extensions posées lors des signatures, les algos
## de chiffrements, les tailees des clés, et bien d'autre choses doivent être réflechis
## afin d'être paramétrés et modifiés en fonction des choix et niveau de confiance recquis.
## Le stockage des méta-informations via le fichier database de openssl est forcement
## limité si on imagine des centaines de clé/certificats.
## Si on utilise ces scripts et/ou app il faut penser à la sécurisation du stockage
## Pas seulement à la sécurité "d'accès" (Ne pas oublier la sécu sur le port de l'app)
######################################################################################
## - Opérations disponibles:
##	create_ca
##	create_client
##	create_server
##	create_pkcs12
##	revoke
##	create_crl
#############################################################
## - arbo de stockage
#  MONAC
#  ├── ca.conf
#  ├── ca.crt
#  ├── ca.key
#  ├── client
#  │   └── adm
#  │       ├── ABCDEF01.pem
#  │       ├── client.crt -> ABCDEF01.pem
#  │       ├── client.csr
#  │       ├── client.key
#  │       ├── rsa_pkcs1
#  │       ├── rsa_pkcs1.pub
#  │       ├── rsa.pub
#  │       └── rsa_ssh2.pub
#  ├── crlnumber
#  ├── database.dat
#  ├── env.sh
#  ├── serial
#  └── server
#      └── paratus
#          ├── ABCDEF02.pem
#          ├── rsa_pkcs1
#          ├── rsa_pkcs1.pub
#          ├── rsa.pub
#          ├── rsa_ssh2.pub
#          ├── server.crt -> ABCDEF02.pem
#          ├── server.csr
#          └── server.key
#############################################################
## Nécessite (pre requirements):
## 1 - openssl & ssh-keygen
##	Pour les opérations de "pki" création/manipulation des clés et certificats
## 2 - socat
##	Pour le "serveur" CRL minimaliste qui renvoi QUE le fichier CRL (quoi qu'on lui demande)
## Si utilisation de l'application "flask"
## 3 - python3.9 (ou +)
##	Modules: cryptography,rsa,hashlib,flask,gunicorn
#############################################################

#####################################################################################################
## La suite de ce README explique comment utiliser directement les scripts shell/bash
## (implementant les opérations listées plus haut)
##
## Pour l'utilisation via l'app python/flask (GUI de management des certifs)
./app.sh
Usage: ./app.sh <start|stop|reload>

Avant de "start" l'application lors de la premiere utilisation:
1- Se déplacer dans le répertoire racine de l'outil (contenant les scripts create_* et app.sh)
2- Dans le script app.sh (vi app.sh)
   Mettre à jour la variable ACTIVATEENV sur la ligne 3
	pour donner la "bonne" commande d'activation de l'environnement python (conda ou autre ...)
   Mettre à jour la variable BINDHOST sur la ligne 4
	pour donner la "bonne" IP ou FQDN ou hostname
	ou BINDHOST=0.0.0.0
	(Sinon faut des tunnels !!)
   :wq !! :-) ;-) :-) ;-) !!
3- ./app.sh start
	Puis RDV dans un navigateur:
	- https://localhost:5001/pki/			-> Racine de l'app
	- https://localhost:5001/pki/intro.html		-> Introduction rapide du vocabulaire
#####################################################################################################

## Création AUTHORITY:
#######################
Verif les params minimaux dans env.sh
	Qui ne seront utile QUE pour create_ca
Verif conf de base openssl dans create_ca (Si désire de modification des "defaults")

./create_ca
=> Init la structure de data dans un repertoire ./${ACNAME}/
contient :
        env.sh
	ca.conf
	ca.crt & ca.key
	database.txt*
	serial*
Les repertoires:
	client
	server

Lors des opérations:
	create_server
	create_client
	create_crl
	revoke
Il faut que la variable ACNAME soit 'export' pour ensuite utiliser correctement les fichiers env.sh par Authorité
les fichiers database.txt* et serial* seront utilisés et mise à jour par openssl

## Création id server:
#######################
export ACNAME=MonAC
./create_server server.nomdomain.fr
=> Créé un clé privé (.key)
   puis une demande de certificat (.csr)
   puis signe avec le ca pour obtenir un "certificat serveur" (.crt)
stockage dans  ./cadata/server/server.nomdomain.fr/

## Création id client:
#######################
export ACNAME=MonAC
./create_client NomDuClient
=> Créé un clé privé (.key)
   puis une demande de certificat (.csr)
   puis signe avec le ca pour obtenir un "certificat client" (.crt)
stockage dans  ./cadata/client/NomDuClient/

## Création d'un pkcs12 (ou pfx) pour import key+crt dans un navigateur client
###############################################################################
export ACNAME=MonAC
./create_pkcs12 NomDuClient
=> Demande un password pour créé un fichier pkcs12 contenant clé privé du client et certificat
   création du fichier ./cadata/client/NomDuClient/client.pfx

## Révocation d'un certificat
##############################
export ACNAME=MonAC
Puis:
./revoke NomDuClient
OU
./revoke server.nomdomain.fr
=> Révocation du certifcat (client ou server) dans la database ./cadata/database.txt
   Supp du fichier (lien symbolique) .crt dans le repertoire du client ou du serveur
   cad ./cadata/client/NomDuClient/client.crt
   OU  ./cadata/server/server.nomdomain.fr/server.crt

## Création d'une CRL (Certificate Revoke List)
##############################################
export ACNAME=MonAC
./create_crl
=> création du ficher 'crl' dans ./${ACNAME}/ca.crl
################################
## Start CRL server distribution
################################
export ACNAME=MonAC
./crlstart &
OU
./crlstart MonAC &

## ATTENTION le 'endpoint' de distribution de la crl est à definir correctement à l'init + Cf env.sh

## Read et dump infos des certificats 
#######################################
- en python
app/dump_certs.py
- en shell
cat ./cadata/database.txt

## 'Unrevoke' certif
# !! Must not be done !!!
#########################
vi ./cadata/database.txt
=> Modif le R en V sur la bonne ligne ... puis save&exit
./create_crl
ln -s ./cadata/client/NomDuClient/client.crt <SERIAL.pem>

