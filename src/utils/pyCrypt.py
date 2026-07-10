#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
A pure‑Python replacement for the original script that wrapped the OpenSSL CLI.
It uses the `cryptography` library and reproduces the file format
produced by:
    openssl enc -aes-256-cbc -pbkdf2 -salt -k <password>

Only the parts you actually used are implemented:
  * PBKDF2‑HMAC‑SHA256 key derivation (OpenSSL default)
  * AES‑256‑CBC with PKCS7 padding
  * OpenSSL “enc” file header: b'Salted__' + 8‑byte salt
  * gzip + pickle (protocol 4) for object (de)serialization
  * helpers to generate a key or a binary key‑file
"""
import base64, gzip, os, pickle, time
from pathlib import Path
from typing import Any, List

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ----------------------------------------------------------------------
# Core class – mimics the original `crypto` base class
# ----------------------------------------------------------------------
class CryptoAES:
    """
    Base class that knows how to turn a *password* (or a file containing a raw
    binary key) into the 256‑bit key required by AES‑256‑CBC.
    """
    def __init__(self, key):
      if os.path.isfile(key):
        self.key = self._read_keyfile(key)
      else:
        if isinstance(key,str):
          self.key = key.encode()
        else:
          self.key = key
      self.iterations: int = 100000
      self.backend = default_backend()

    # ------------------------------------------------------------------
    # Helpers functions
    # ------------------------------------------------------------------
    @staticmethod
    def _load_obj(blob: bytes) -> Any:
        """ RestoreObject (with pickle & gzip) """
        return pickle.loads(gzip.decompress(blob))
    @staticmethod
    def _dump_obj(obj: Any) -> bytes:
        """Pickle (protocol 4) + gzip‑compress an arbitrary Python object."""
        return gzip.compress(pickle.dumps(obj, protocol=4))

    @staticmethod
    def _read_keyfile(path: os.PathLike) -> bytes:
        """Read a raw binary key file (exactly what `openssl rand -writerand` writes)."""
        return Path(path).read_bytes()
    @staticmethod
    def genere_key(size_bytes: int = 32) -> str:
        return os.urandom(size_bytes)

    @staticmethod
    def genere_keyfile(path: os.PathLike, size_bytes: int = 32) -> None:
        """ Write a raw binary key """
        Path(path).write_bytes(os.urandom(size_bytes))

    # ------------------------------------------------------------------
    #  Encryption / Decryption (OpenSSL‑compatible)
    # ------------------------------------------------------------------
    def _derive_key(self, salt: bytes) -> bytes:
        """ Password‑based key derivation
        Derive a 32‑byte (256‑bit) key from either:
          * a password string/bytes (OpenSSL `-k` flag) or
        The function mimics OpenSSL’s `enc -pbkdf2 -salt` algorithm:
          * PBKDF2‑HMAC‑SHA256
          * 8‑byte salt (the same salt that will be stored in the file)
          * 100 000 iterations (default for recent OpenSSL releases)
        """
        kdf = PBKDF2HMAC( algorithm=hashes.SHA256(), length=32, salt=salt,
                          iterations=self.iterations, backend=self.backend )
        return kdf.derive(self.key)

    def _encrypt_blob(self, plaintext: bytes, salt: bytes, iv: bytes) -> bytes:
        key = self._derive_key(salt)
        cipher = Cipher( algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded = padder.update(plaintext) + padder.finalize()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        return ciphertext

    def _decrypt_blob(self, ciphertext: bytes, salt: bytes, iv: bytes) -> bytes:
        key = self._derive_key(salt)
        cipher = Cipher( algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        return unpadder.update(padded) + unpadder.finalize()

    # ------------------------------------------------------------------
    #           Publics API
    # ------------------------------------------------------------------
    def encrypt_dump(self, obj: Any, outfile: os.PathLike) -> bool:
        """
        Serialize + compress + encrypt ``obj`` and write the result to ``outfile``.
        The file layout is the same as OpenSSL's `enc` format: b"Salted__" + 8‑byte salt + 16‑byte IV + ciphertext
        """
        # Generate random salt (8 bytes) and IV (16 bytes)
        salt = os.urandom(8)
        iv = os.urandom(16)
        # Serialize, compress & Encrypt
        cipher_blob = self._encrypt_blob(self._dump_obj(obj), salt, iv)
        # write to file with "OpenSSL header"
        Path(outfile).write_bytes(b"Salted__" + salt + iv + cipher_blob)
        return True

    def decrypt_load(self, infile: os.PathLike) -> Any:
        """
        Read an OpenSSL‑compatible encrypted file, decrypt it and return the original Python object.
        """
        data = Path(infile).read_bytes()
        if not data.startswith(b"Salted__"):
            raise ValueError("File does not start with OpenSSL 'Salted__' header")
        # Extract the three pieces that OpenSSL would have used
        salt = data[8:16]          # 8‑byte salt
        iv = data[16:32]           # 16‑byte IV (AES block size)
        ciphertext = data[32:]    # the rest is ciphertext

        # Decrypt, dezip and then deserialize
        return self._load_obj( self._decrypt_blob(ciphertext, salt, iv) )

# ----------------------------------------------------------------------
def get_data(nbl: int = 100000, nbs: int = 128) -> List[List[Any]]:
    """ Produce random data to test purposes """
    import random
    import string
    data = []
    t0 = time.time()
    for i in range(1, nbl):
        lib1 = "".join(random.choice(string.printable) for _ in range(nbs))
        lib2 = "".join(random.choice(string.printable) for _ in range(nbs))
        data.append([i, chr(i), lib1, lib2])
    print(f"data generated {time.time() - t0:.2f}s")
    return data


# ---------------------------------------
# ------- MAIN TESTS --------------------
# ---------------------------------------
if __name__ == "__main__":
    # ------------------------------------------------------------------
    # Prepare test data and few keys
    # ------------------------------------------------------------------
    data = get_data()
    key_file = "my.key"
    CryptoAES.genere_keyfile(key_file)    # creates a raw 32‑byte key
    keys=['MonS3cret-Que-N0B0dy-2@1T', CryptoAES.genere_key(), key_file ]
    # ------------------------------------------------------------------
    # Loop over the three possibilities and encrypt / decrypt
    # ------------------------------------------------------------------
    for idx, pw in enumerate(keys, start=1):
        crypto = CryptoAES(pw)

        enc_file = f"data{idx}.enc"
        print(f"\n==> {enc_file}  –  key = {pw} <==")

        # ---- encrypt ---------------------------------------------------
        t0 = time.time()
        crypto.encrypt_dump(data, enc_file)
        print(f"  encrypt + write : {time.time() - t0:.3f}s")

        # ---- decrypt ---------------------------------------------------
        t0 = time.time()
        loaded = crypto.decrypt_load(enc_file)
        print(f"  decrypt + read  : {time.time() - t0:.3f}s")

        # ---- sanity check -----------------------------------------------
        print(f"  type={type(loaded)}  len={len(loaded)}")
        assert loaded == data, "round‑trip failed!"
    print("\nAll seems good.")

