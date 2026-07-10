# -*- coding: utf-8 -*-
"""
Equivalent pure‑Python of the OpenSSL wrapper you posted.

All functions keep the same signature:
    encrypt(key_path, message, key_is_cert=False) -> (str, str)
    decrypt(key_path, b64_message)                -> (str, str)
    sign(key_path, message)                       -> (str, str)
    verify(key_path, message, b64_sig, key_is_cert=False) -> (str, str)

The second element of each tuple is the “command” that would have been
executed with subprocess – useful for debugging / logs.
"""

import base64
import textwrap
from pathlib import Path
from typing import Tuple, Union

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# ----------------------------------------------------------------------
# Helper utilities
# ----------------------------------------------------------------------
def _load_private_key(pem_path: Union[str, Path], password: bytes = None) -> rsa.RSAPrivateKey:
    """Read a PEM‑encoded RSA private key."""
    data = Path(pem_path).read_bytes()
    return serialization.load_pem_private_key(data, password=password, backend=default_backend())

def _load_public_key(pem_path: Union[str, Path]) -> rsa.RSAPublicKey:
    """Read a PEM‑encoded RSA public key (or a PEM‑encoded X.509 cert)."""
    data = Path(pem_path).read_bytes()
    # Try certificate first – it contains a public key
    try:
        cert = x509.load_pem_x509_certificate(data, backend=default_backend())
        return cert.public_key()
    except ValueError:
        # Not a cert → assume a plain public key
        return serialization.load_pem_public_key(data, backend=default_backend())

def _b64_wrap(b: bytes, width: int = 70) -> str:
    """Base‑64 encode *b* and insert a line‑break every *width* characters."""
    return "\n".join(textwrap.wrap(base64.b64encode(b).decode(), width))

# ----------------------------------------------------------------------
# 1️⃣  encrypt
# ----------------------------------------------------------------------
def encrypt(mikey: str, message: str, key_is_cert: bool = False) -> Tuple[str, str]:
    """
    RSA‑ES‑PKCS1‑v1_5 encryption (exactly what ``openssl pkeyutl -encrypt`` does).

    Parameters
    ----------
    mikey : str
        Path to the PEM‑encoded public key **or** X.509 certificate.
    message : str
        Plain‑text to encrypt.
    key_is_cert : bool, optional
        Kept only for API compatibility – the function automatically detects a
        certificate when the PEM starts with ``-----BEGIN CERTIFICATE-----``.

    Returns
    -------
    (ciphertext_base64, pseudo_cmd) : Tuple[str, str]
        *ciphertext_base64* is the encrypted data, wrapped at 70 chars per line.
        *pseudo_cmd* is a string that mimics the OpenSSL command line you used
        before (useful for logs).
    """
    # ----- Build a “pseudo‑command” for debugging -----------------------
    pseudo_cmd = f"openssl pkeyutl -encrypt -pubin -inkey {mikey}"
    if key_is_cert:
        pseudo_cmd += " -certin"

    # ----- Load the public key (or the cert that contains it) ------------
    pub_key = _load_public_key(mikey)

    # ----- OpenSSL strips CR and does NOT add a trailing newline ----------
    # (the original code used ``echo -n``).  We do the same.
    message_bytes = message.replace("\r", "").encode()

    # ----- Perform the RSA encryption ------------------------------------
    encrypted = pub_key.encrypt(
        message_bytes,
        padding.PKCS1v15()                 # RSAES‑PKCS1‑v1_5
    )

    # ----- Return base64 with line‑breaks --------------------------------
    b64_cipher = _b64_wrap(encrypted, 70)
    return b64_cipher, pseudo_cmd


# ----------------------------------------------------------------------
# 2️⃣  decrypt
# ----------------------------------------------------------------------
def decrypt(mikey: str, message: str) -> Tuple[str, str]:
    """
    RSA‑ES‑PKCS1‑v1_5 decryption (the counterpart of ``encrypt``).

    Parameters
    ----------
    mikey : str
        Path to the PEM‑encoded RSA **private** key.
    message : str
        Base‑64 encoded ciphertext (may contain line‑breaks).

    Returns
    -------
    (plaintext, pseudo_cmd) : Tuple[str, str]
    """
    pseudo_cmd = f"openssl pkeyutl -decrypt -inkey {mikey}"

    # Load private key
    priv_key = _load_private_key(mikey)

    # Decode base64 (ignore whitespace / new‑lines)
    ciphertext = base64.b64decode(message)

    # Decrypt
    plaintext_bytes = priv_key.decrypt(
        ciphertext,
        padding.PKCS1v15()                 # RSAES‑PKCS1‑v1_5
    )
    # OpenSSL’s ``-decrypt`` writes the raw bytes to stdout – we decode
    # using UTF‑8 with *ignore* for any non‑textual bytes (same behaviour as
    # ``errors='ignore'`` in your original script).
    plaintext = plaintext_bytes.decode(errors="ignore")
    return plaintext, pseudo_cmd


# ----------------------------------------------------------------------
# 3️⃣  sign
# ----------------------------------------------------------------------
def sign(mikey: str, message: str) -> Tuple[str, str]:
    """
    RSA‑PKCS1‑v1_5 signature with SHA‑512 (exactly what the
    ``openssl dgst -sha512 -binary | openssl pkeyutl -sign`` pipeline does).

    Parameters
    ----------
    mikey : str
        Path to the PEM‑encoded RSA **private** key.
    message : str
        Data that must be signed.

    Returns
    -------
    (signature_base64, pseudo_cmd) : Tuple[str, str]
    """
    pseudo_cmd = f"openssl dgst -sha512 -binary | openssl pkeyutl -sign -inkey {mikey}"

    # Load private key
    priv_key = _load_private_key(mikey)

    # Same preprocessing as the original script
    msg = message.replace("\r", "").replace("'", "'\\''").encode()

    # Compute SHA‑512 digest (OpenSSL does it internally, we do it explicitly)
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(msg)
    hashed = digest.finalize()

    # Sign the digest (PKCS#1 v1.5 padding)
    signature = priv_key.sign(
        hashed,
        padding.PKCS1v15(),
        hashes.SHA512()
    )

    # Return base64 wrapped at 70 chars (identical to the original)
    b64_sig = _b64_wrap(signature, 70)
    return b64_sig, pseudo_cmd


# ----------------------------------------------------------------------
# 4️⃣  verify
# ----------------------------------------------------------------------
def verify(mikey: str,
           message: str,
           verifmess: str,
           key_is_cert: bool = False) -> Tuple[str, str]:
    """
    RSA‑PKCS1‑v1_5 signature verification with SHA‑512 (the counterpart of ``sign``).

    Parameters
    ----------
    mikey : str
        Path to the PEM‑encoded RSA **public** key **or** X.509 certificate.
    message : str
        Original clear‑text that was signed.
    verifmess : str
        Base‑64 encoded signature (may contain line‑breaks).
    key_is_cert : bool, optional
        Kept for API compatibility – the function automatically detects a
        certificate when the PEM starts with ``-----BEGIN CERTIFICATE-----``.

    Returns
    -------
    (verification_output, pseudo_cmd) : Tuple[str, str]
        ``verification_output`` is the exact stdout that OpenSSL would have
        printed (e.g. ``Verified OK`` or an error message).
    """
    pseudo_cmd = f"openssl dgst -sha512 -binary | openssl pkeyutl -verify -pubin -inkey {mikey}"
    if key_is_cert:
        pseudo_cmd += " -certin"

    # Load public key (or cert)
    pub_key = _load_public_key(mikey)

    # Same preprocessing as the original script
    msg = message.replace("\r", "").encode()

    # Compute SHA‑512 digest of the message
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(msg)
    hashed = digest.finalize()

    # Decode the supplied signature
    try:
        signature = base64.b64decode(verifmess)
    except Exception as exc:
        return f"Decode base64 error: {exc}", pseudo_cmd

    # Perform verification – we mimic OpenSSL’s exit‑code handling:
    #   * success → stdout = "Verified OK"
    #   * failure → raise an exception → we capture its message.
    try:
        pub_key.verify(
            signature,
            hashed,
            padding.PKCS1v15(),
            hashes.SHA512()
        )
        verification_output = "Verified OK"
    except Exception as exc:
        verification_output = f"Verification failed: {exc}"

    return verification_output, pseudo_cmd


# ----------------------------------------------------------------------
# 5️⃣  Small self‑test (run this file directly)
# ----------------------------------------------------------------------
if __name__ == "__main__":
    # Generate a temporary RSA key pair for demo purposes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    import tempfile, os

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Write them to temporary files
    with tempfile.TemporaryDirectory() as td:
        priv_path = os.path.join(td, "priv.pem")
        pub_path = os.path.join(td, "pub.pem")
        Path(priv_path).write_bytes(priv_pem)
        Path(pub_path).write_bytes(pub_pem)

        txt = "Hello world! Ça marche ?"
        print("\n--- ENCRYPT / DECRYPT ------------------------------------------------")
        enc, cmd_enc = encrypt(pub_path, txt)
        print("cmd :", cmd_enc)
        print("cipher (base64) :", enc[:60] + "...")

        dec, cmd_dec = decrypt(priv_path, enc)
        print("cmd :", cmd_dec)
        print("decrypted :", dec)

        print("\n--- SIGN / VERIFY ---------------------------------------------------")
        sig, cmd_sig = sign(priv_path, txt)
        print("cmd :", cmd_sig)
        print("signature (base64) :", sig[:60] + "...")

        verif, cmd_ver = verify(pub_path, txt, sig)
        print("cmd :", cmd_ver)
        print("verification :", verif)

