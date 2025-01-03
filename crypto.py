import streamlit as st
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

# Key derivation function
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

# Encryption function
def encrypt(text: str, password: str) -> str:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(text.encode()) + encryptor.finalize()
    encrypted = urlsafe_b64encode(salt + iv + ciphertext + encryptor.tag).decode()
    return encrypted

# Decryption function
def decrypt(encrypted_text: str, password: str) -> str:
    decoded = urlsafe_b64decode(encrypted_text.encode())
    salt, iv, ciphertext, tag = decoded[:16], decoded[16:28], decoded[28:-16], decoded[-16:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

# Streamlit app
st.title("Cryptography Project with AES-GCM")
st.write("Enter text and password to encrypt and decrypt.")

mode = st.radio("Mode", ["Encrypt", "Decrypt"])

if mode == "Encrypt":
    text = st.text_area("Text to Encrypt")
    password = st.text_input("Password", type="password")
    if st.button("Encrypt"):
        encrypted_text = encrypt(text, password)
        st.text_area("Encrypted Text", encrypted_text)

if mode == "Decrypt":
    encrypted_text = st.text_area("Encrypted Text to Decrypt")
    password = st.text_input("Password", type="password")
    if st.button("Decrypt"):
        try:
            decrypted_text = decrypt(encrypted_text, password)
            st.text_area("Decrypted Text", decrypted_text)
        except Exception as e:
            st.error("Decryption failed. Check your password and encrypted text.")

