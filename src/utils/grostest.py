#! /usr/bin/env python

import pandas as pd
import cx_Oracle
import sqlalchemy
from sqlalchemy.exc import SQLAlchemyError
import sys,time

user = sys.argv[1]
password = sys.argv[2]
tns_alias = sys.argv[3]
# Connection a oracle
con = sqlalchemy.create_engine(f"oracle+cx_oracle://{user}:{password}@{tns_alias}", arraysize=1000)

dt=time.time()
## READ some info et get it in DataFrame
################
try:
   sql2 = """SELECT * FROM VERONE_DGOUV_2024.DGOUV_RELANCE""";
   df = pd.read_sql(sql2, con=con)
   print(df)
except SQLAlchemyError as e:
   print(e)
print(f"After req sql {time.time() - dt}")


from SimpleCrypt import scrypt
a=scrypt("my.key")

# Save data to a crypted file
dt
df=a.encryptdump(df,"data3.enc")
print(f"{df}")
print(f"After encrypt {time.time() - dt}")


# Load a crypted file:
dt
df=a.decryptload("data3.enc")
#print(f"{df}")
print(f"After reload decrypt {time.time() - dt}")

# Simple save without crypt
dt
with open("data.dat","wb") as fh:
     fh.write(a.dumpmsg(df))
print(f"After simple write {time.time() - dt}")

