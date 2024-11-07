import pickle

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
import os
import base64


def encrypt_with_public_key(data, public_key_pem):
    """
    Criptografa dados usando uma chave pública RSA.

    Parâmetros:
        - data (bytes): Dados que serão criptografados (por exemplo, a chave de sessão ChaCha20).
        - public_key_pem (str): A chave pública RSA em formato PEM.

    Retorno:
        - str: Dados criptografados e codificados em base64.
    """
    # Carrega a chave pública a partir do PEM
    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))

    # Criptografa os dados usando a chave pública
    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Retorna os dados criptografados em base64 para facilitar o envio em formato de string
    return base64.b64encode(encrypted_data).decode('utf-8')


def decrypt_with_private_key(encrypted_data, private_key_pem, password=None):
    """
    Descriptografa dados usando uma chave privada RSA.

    Parâmetros:
        - encrypted_data (str): Dados criptografados e codificados em base64.
        - private_key_pem (str): A chave privada RSA em formato PEM.
        - password (str, opcional): Senha para descriptografar a chave privada (se estiver protegida por senha).

    Retorno:
        - bytes: Dados descriptografados (por exemplo, a chave de sessão ChaCha20).
    """
    # Decodifica os dados criptografados de base64
    encrypted_data_bytes = base64.b64decode(encrypted_data)

    # Carrega a chave privada a partir do PEM
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=password.encode('utf-8') if password else None
    )

    # Descriptografa os dados usando a chave privada
    decrypted_data = private_key.decrypt(
        encrypted_data_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return decrypted_data


# Criptografar mensagem com ChaCha20
def encrypt_chacha20_message(key, message):
    nonce = os.urandom(16)  # ChaCha20 exige um nonce de 16 bytes
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.b64encode(nonce + ciphertext).decode('utf-8')


# Descriptografar mensagem com ChaCha20
def decrypt_chacha20_message(key, encrypted_message):
    decoded_data = base64.b64decode(encrypted_message.encode('utf-8'))
    nonce, ciphertext = decoded_data[:16], decoded_data[16:]
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# ---------- Cryptography for private key -------------

def derive_key(password: str, salt: bytes) -> bytes:
    # Configuração do KDF com PBKDF2 e SHA-256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Chave de 256 bits para AES
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    # Deriva e retorna a chave criptográfica
    return kdf.derive(password.encode())


def encrypt_private_key(private_key: bytes, password: str) -> dict:
    # Gera um salt e uma chave derivada
    salt = os.urandom(16)  # 16 bytes de salt
    key = derive_key(password, salt)

    # Gera um nonce para o AES-GCM
    nonce = os.urandom(12)  # 12 bytes para AES-GCM

    # Criptografa a chave privada
    aesgcm = AESGCM(key)
    encrypted_private_key = aesgcm.encrypt(nonce, private_key, None)

    # Retorna os valores necessários para descriptografia futura
    return {
        'salt': salt,
        'nonce': nonce,
        'encrypted_key': encrypted_private_key
    }


def decrypt_private_key(encrypted_data: dict, password: str) -> bytes:
    # Extrai o salt, nonce e a chave criptografada
    salt = encrypted_data['salt']
    nonce = encrypted_data['nonce']
    encrypted_key = encrypted_data['encrypted_key']

    # Deriva a chave usando o mesmo salt
    key = derive_key(password, salt)

    # Descriptografa a chave privada
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, encrypted_key, None)


def save_private_key(encrypted_data, username):
    filename = f"{username}_key.bin"
    file_path = f"users_key/{filename}"
    try:
        # Verifica se o diretório de destino existe
        directory = os.path.dirname(file_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)  # Cria o diretório se ele não existir

        # Salva o dicionário em um arquivo binário
        with open(file_path, "wb") as f:
            pickle.dump(encrypted_data, f)

        print("DEBUG: A chave privada foi armazenada do lado do cliente")
        return True

    except (OSError, pickle.PickleError) as e:
        # Captura erros de I/O e erros específicos do módulo pickle
        print(f"Erro ao salvar a chave privada criptografada: {e}")
        return False


def recover_private_key(username):
    # Carregando e decodificando do JSON
    try:
        filename = f"{username}_key.bin"
        file_path = f"users_key/{filename}"
        with open(file_path, "rb") as f:
            loaded_encrypted_data = pickle.load(f)
        return loaded_encrypted_data

    except (OSError, pickle.PickleError) as e:
        print(f"Erro ao abrir a chave privada criptografada: {e}")
        return False