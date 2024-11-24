import pickle

from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import os
import base64


RSA_KEY_SIZE = 2048


def generate_keypair():
    private_key = RSA.generate(RSA_KEY_SIZE)
    public_key = private_key.publickey()
    return private_key.export_key(), public_key.export_key()


def encrypt_with_public_key(data, public_key_pem):
    """
    Criptografa dados usando uma chave pública RSA.
    """
    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_data).decode('utf-8')


def decrypt_with_private_key(encrypted_data, private_key_pem, password=None):
    """
    Descriptografa dados usando uma chave privada RSA.
    """
    # Valida e decodifica os dados criptografados
    try:
        encrypted_data_bytes = base64.b64decode(encrypted_data)
    except Exception as e:
        raise ValueError("Falha ao decodificar encrypted_data: não é um Base64 válido.") from e

    # Valida a chave privada PEM
    if isinstance(private_key_pem, str):
        private_key_pem = private_key_pem.encode('utf-8')
    if not private_key_pem.startswith(b"-----BEGIN RSA PRIVATE KEY-----"):
        raise ValueError("Chave privada inválida ou não está no formato PEM.")

    # Carrega a chave privada
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=password.encode('utf-8') if password else None
        )
    except ValueError as e:
        raise ValueError("Falha ao carregar a chave privada. Verifique a senha ou o formato da chave.") from e

    # Descriptografa os dados
    try:
        decrypted_data = private_key.decrypt(
            encrypted_data_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except ValueError as e:
        raise ValueError("Erro na descriptografia: verifique os dados criptografados e a chave privada.") from e

    return decrypted_data


def encrypt_chacha20_message(key, message):
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.b64encode(nonce + ciphertext).decode('utf-8')


def decrypt_chacha20_message(key, encrypted_message):
    decoded_data = base64.b64decode(encrypted_message.encode('utf-8'))
    nonce, ciphertext = decoded_data[:16], decoded_data[16:]
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    return (decryptor.update(ciphertext) + decryptor.finalize()).decode('utf-8')


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_private_key(private_key: bytes, password: str) -> dict:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    nonce = os.urandom(12)

    aesgcm = AESGCM(key)
    encrypted_private_key = aesgcm.encrypt(nonce, private_key, None)

    return {
        'salt': salt,
        'nonce': nonce,
        'encrypted_key': encrypted_private_key
    }


def decrypt_private_key(encrypted_data: dict, password: str) -> bytes:
    salt = encrypted_data['salt']
    nonce = encrypted_data['nonce']
    encrypted_key = encrypted_data['encrypted_key']

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, encrypted_key, None)


def save_private_key(encrypted_data, username):
    filename = f"{username}_key.bin"
    file_path = f"users_key/{filename}"
    try:
        directory = os.path.dirname(file_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)

        with open(file_path, "wb") as f:
            pickle.dump(encrypted_data, f)

        print("DEBUG: A chave privada foi armazenada do lado do cliente")
        return True

    except (OSError, pickle.PickleError) as e:
        print(f"Erro ao salvar a chave privada criptografada: {e}")
        return False


def recover_private_key(username):
    try:
        filename = f"{username}_key.bin"
        file_path = f"users_key/{filename}"
        with open(file_path, "rb") as f:
            loaded_encrypted_data = pickle.load(f)
        return loaded_encrypted_data

    except (OSError, pickle.PickleError) as e:
        print(f"Erro ao abrir a chave privada criptografada: {e}")
        return False


def encrypt_session_key(session_key: bytes, room: str) -> dict:
    salt = os.urandom(16)
    key = derive_key(room, salt)
    nonce = os.urandom(12)

    aesgcm = AESGCM(key)
    encrypted_private_key = aesgcm.encrypt(nonce, session_key, None)

    return {
        'salt': salt,
        'nonce': nonce,
        'encrypted_key': encrypted_private_key
    }


def decrypt_session_key(encrypted_data: dict, room: str) -> bytes:
    salt = encrypted_data['salt']
    nonce = encrypted_data['nonce']
    encrypted_key = encrypted_data['encrypted_key']

    key = derive_key(room, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, encrypted_key, None)


def save_session_key(encrypted_data, room):
    # Sem alterações.
    filename = f"{room}_session_key.bin"
    file_path = f"session_keys/{filename}"
    try:
        directory = os.path.dirname(file_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)

        with open(file_path, "wb") as f:
            pickle.dump(encrypted_data, f)

        print("DEBUG: A session key foi armazenada do lado do cliente.")
        return True

    except (OSError, pickle.PickleError) as e:
        print(f"Erro ao salvar a session key criptografada: {e}")
        return False


def recover_session_key(room):
    try:
        filename = f"{room}_session_key.bin"
        file_path = f"session_keys/{filename}"
        with open(file_path, "rb") as f:
            loaded_encrypted_data = pickle.load(f)
        return loaded_encrypted_data

    except (OSError, pickle.PickleError) as e:
        print(f"Erro ao abrir a session key criptografada: {e}")
        return False
