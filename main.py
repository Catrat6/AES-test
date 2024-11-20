from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import os
import base64

# encrypt with AES function set, I used AI to quickly write these

def derive_key(password, salt):
    """Derive a 256-bit key from the password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt(plaintext, password):
    """Encrypt the plaintext using AES."""
    salt = os.urandom(16)  # Generate a random salt
    key = derive_key(password, salt)
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = PKCS7(128).padder()  # Pad plaintext to make it a multiple of the block size
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(salt + iv + ciphertext).decode()  # Combine salt, IV, and ciphertext

def decrypt(encrypted_data, password):
    """Decrypt the encrypted data using AES."""
    data = base64.b64decode(encrypted_data)
    salt, iv, ciphertext = data[:16], data[16:32], data[32:]

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()  # Remove padding from the plaintext
    plaintext = unpadder.update(padded_data) + unpadder.finalize()

    return plaintext.decode()


# Then I made a loop to run the functions in a CLI program

program_state = True

while program_state:

    input('Welcome to your simple AES encryption tool! Press enter to get started!\n')

    action_choice = input('Would you like to encrypt or decrypt?\n').lower()

    if action_choice == 'encrypt':
        message = input('What is your message?\n')
        key = input('What is your password/key?\n')

        encrypted_message = encrypt(message, key)

        print(f'Here is your encrypted message: {encrypted_message}')

    elif action_choice == 'decrypt':
        e_message = input('Paste in your encrypted message:\n')
        e_key = input('Input your password/key:\n')

        decrypted_message = decrypt(e_message, e_key)

        print(f'Here is your decrypted message: {decrypted_message}')


    again = input('Would you like to encrypt/decrypt another message?\n').lower()

    if again in ['no', 'n', 'not', 'done', 'exit']:
        break
    else:
        continue

