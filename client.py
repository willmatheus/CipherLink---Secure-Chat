import os
import json
import requests
import socketio
import random
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import ChaCha20
from base64 import b64encode, b64decode
from hashlib import pbkdf2_hmac

# Cryptography lib for private key
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pickle


# Inicializando o cliente SocketIO
sio = socketio.Client()
RSA_KEY_SIZE = 2048
session_key = None

# ---------- Cryptography auxiliary functions -------------

def generate_keypair():
    private_key = RSA.generate(RSA_KEY_SIZE)
    public_key = private_key.publickey()
    return private_key.export_key(), public_key.export_key()


def encrypt_message(message, session_key):
    # Gera um nonce aleatório de 12 bytes para ChaCha20
    nonce = get_random_bytes(12)
    cipher = ChaCha20.new(key=session_key, nonce=nonce)
    ciphertext = cipher.encrypt(message.encode())
    # Retorna o nonce + ciphertext codificados em base64
    return b64encode(nonce + ciphertext).decode()


def decrypt_message(encrypted_message, session_key):
    # Decodifica a mensagem base64 e separa o nonce e o ciphertext
    raw = b64decode(encrypted_message)
    nonce, ciphertext = raw[:12], raw[12:]
    cipher = ChaCha20.new(key=session_key, nonce=nonce)
    # Descriptografa o texto e o retorna decodificado
    return cipher.decrypt(ciphertext).decode()


# ---------- Friendlist Functions -------------
def add_user_in_friendlist(username, username_to_add):
    friendlist = []
    friendlist = get_friend_list(username)
    if not username_to_add in friendlist:
        response = requests.post('http://localhost:5000/user', json={
            'username': username,
            'username_to_add': username_to_add
        })
        if response.ok:
            print("Usuario adicionado com sucesso")
        else:
            print("Usuario nao encontrado")
    else:
        print("Esse usuario ja esta na sua lista de amigos")


def is_user_in_friendlist(username, username_to_talk):
    response = requests.post('http://localhost:5000/frienlist', json={
        'username': username,
        'username_to_talk': username_to_talk
    })
    if response.ok:
        return True
    return False


def get_friend_list(username):
    response = requests.get(f'http://localhost:5000/friendlist/{username}')
    if response.ok:
        friend_list = response.json().get("friends", [])
        return friend_list
    else:
        print("Erro ao obter a lista de amigos.")
        return []


# ---------- Chat Functions -------------
# Disparar evento de início de sessão via SocketIO
def start_session(username_a, username_b):
    sio.emit('start_session', {'username_a': username_a, 'username_b': username_b})


# Receber confirmação de início de sessão e definir a chave de sessão
@sio.on('session_started')
def on_session_started(data):
    global session_key
    if 'key' in data:
        session_key = b64decode(data['key'])
        print("Sessão iniciada com sucesso!")
    else:
        print("Erro ao iniciar a sessão.")


# Enviar mensagem criptografada
def send_message(username_a, username_b, message):
    if session_key:
        encrypted_message = encrypt_message(message, session_key)
        sio.emit('send_message', {
            'username_a': username_a,
            'username_b': username_b,
            'message': encrypted_message
        })
    else:
        print("Sessão não estabelecida. Inicie uma sessão primeiro.")


# Lidar com mensagens recebidas
@sio.on('receive_message')
def handle_receive_message(data):
    if session_key:
        message = decrypt_message(data['message'], session_key)
        print(f"Mensagem recebida: {message}")


# ---------- User Functions -------------

def get_all_users():
    response = requests.get('http://localhost:5000/all_users')
    if response.ok:
        all_users = response.json().get("users", [])

        return all_users
    else:
        print("Erro ao obter a lista de usuários.")
        return []

# Funções de API para registro e login
def register_user(username, password):
    private_key, public_key = generate_keypair()

    print("\nDEBUG: Chaves geradas:")
    # print(f"DEBUG: Chave publica: {public_key.decode()}")
    # print(f"DEBUG: Chave privada: {private_key.decode()}")

    response = requests.post('http://localhost:5000/register', json={
        'username': username,
        'password': password,
        'public_key': public_key.decode()
    })
    encrypted_data = encrypt_private_key(private_key, password)
    print("DEBUG: Chave privada criptografada")
    save_private_key(username=username, encrypted_data=encrypted_data)
    return response.ok


def login_user(username, password, sid):
    response = requests.post('http://localhost:5000/login', json={
        'username': username,
        'password': password,
        'sid': sid,
    })

    if response.ok:
        private_key_encrypted = recover_private_key(username)
        private_key = decrypt_private_key(private_key_encrypted, password)

        print("DEBUG: Chave privada recuperada")
        #print(private_key.decode())
        print("\nLogin bem-sucedido!")
        print("Mensagens offline:", response.json().get('offline_messages', []))
        return True, private_key

    print("\nFalha no login.")
    return False

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
    private_key = aesgcm.decrypt(nonce, encrypted_key, None)

    return private_key


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


# ---------- Interface functions -------------

def chat_with_user(username, user_to_talk):
    print(f"\n╔═════════════════╗")
    print(f" Chat com {user_to_talk}")
    print("╚═════════════════╝")
    print("Digite 'sair' para voltar ao menu principal.\n")

    while True:
        message = input("Você: ")
        if message.lower() == "sair":
            print("Voltando ao menu principal.")
            break
        send_message(username, user_to_talk, message)


def main_menu(username):
    while True:
        print("\n╔═════════════════╗")
        print("  CipherLink Chat")
        print("╚═════════════════╝")
        print("1 - Adicionar um usuario")
        print("2 - Conversar com um usuario na sua lista de amigos")
        print("3 - Sair do programa")
        
        choice = input("Digite sua opcao: ")
        
        if choice == "1":
            # Obtenha e exiba a lista de todos os usuários do sistema
            all_users = get_all_users()
            friend_list = get_friend_list(username)
            all_users_avaliable = list(set(all_users) - set(friend_list))
            if all_users:
                print("\nUsuarios disponíveis para adicionar:")
                for user in all_users_avaliable:
                    if user != username:  # Exclui o próprio usuário da lista
                        print(f" - {user}")
            else:
                print("Nenhum usuario encontrado no sistema.")
            
            # Continuar pedindo para digitar o nome do usuário que deseja adicionar
            user_to_add = input("Digite o nome do usuario que deseja adicionar: ")
            add_user_in_friendlist(username, user_to_add)
        elif choice == "2":
            friend_list = get_friend_list(username)
            if friend_list:
                print("\nLista de amigos:")
                for friend in friend_list:
                    print(f" - {friend}")
            else:
                print("Voce nao tem amigos adicionados ainda.")
            
            user_to_talk = input("Digite o nome do usuario da lista de amigos que voce quer conversar: ")
            if not is_user_in_friendlist(username, user_to_talk):
                print("Usuario nao encontrado na lista de amigos.")
                continue
            
            start_session(username, user_to_talk)
            chat_with_user(username, user_to_talk)
        elif choice == "3":
            print("Encerrando o programa. Ate logo!")
            break
        else:
            print("Opcao Invalida!")


# Função principal para execução do chat
def run_chat():
    # Conectar ao servidor SocketIO
    sid = str(random.getrandbits(128))
    sio.connect('http://localhost:5000/login', headers={'sid': sid})
    #sio.connect('http://192.168.1.7:5000', headers={'sid': sid})

    print("\n")

    print(  "      ...             .                                                               ...         .                        ..    ")
    print(  "      ...             .                                                               ...         .                        ..     ")
    print(  '   xH88"`~ .x8X      @88>                  .uef^"                                 .zf"` `"tu     @88>                < .z@8"`      ')
    print(""" :8888   .f"8888Hf   %8P    .d``         :d88E                     .u    .       x88      '8N.   %8P      u.    u.    !@88E        """)
    print(  ":8888>  X8L  ^""`     .      @8Ne.   .u   `888E            .u     .d88B :@8c      888k     d88&    .     x@88k u@88c.  '888E   u ")
    print("""X8888  X888h        .@88u   %8888:u@88N   888E .z8k    ud8888.  ="8888f8888r     8888N.  @888F  .@88u  ^"8888""8888"   888E u@8NL  """)
    print("""88888  !88888.     ''888E`   `888I  888.  888E~?888L :888'8888.   4888>'88"      `88888 9888%  ''888E`   8888  888R    888E`"88*"  """)
    print("""88888   %88888       888E     888I  888I  888E  888E d888 '88%"   4888> '          %888 "88F     888E    8888  888R    888E .dN.   """)
    print("""88888 '> `8888>      888E     888I  888I  888E  888E 8888.+"      4888>             8"   "*h=~   888E    8888  888R    888E~8888   """)
    print(  "`8888L %  ?888   !   888E   uW888L  888'  888E  888E 8888L       .d888L .+        z8Weu          888E    8888  888R    888E '888&  ")
    print(""" `8888  `-*""   /    888&  '*88888Nu88P   888E  888E '8888c. .+  ^"8888*"        ""88888i.   Z   888&   "*88*" 8888"   888E  9888. """)
    print("""   "888.      :"     R888" ~ '88888F`    m888N= 888>  "88888%       "Y"         "   "8888888*    R888"    ""   'Y"   '"888*" 4888" """)
    print("""     `""***~"`        ""      888 ^       `Y"   888     "YP'                          ^"**""      ""                    ""    ""   """)
    print("""                              *8E              J88"                                                                                """)
    print("""                              '8>              @%                                                                                  """)
    print("""                               "             :"                                                                                    """)

    print("\nOla, seja bem vindo ao CipherLink!\n")

    while True:
        print("\nDeseja logar (l) ou se registrar (r)?")
        option = input()
        
        # Register
        if option == 'r':
            username = input("\nDigite seu nome de usuario: ")
            password = input("Digite sua senha: ")
            if register_user(username, password):
                print("Cadastro realizado com sucesso!")
                main_menu(username)
                break  # Sai do loop após o registro e chamada do menu principal

        # Login
        elif option == 'l':
            print("\n╔═══════════════╗")
            print("      Login")
            print("╚═══════════════╝")
            username = input("\nDigite seu nome de usuario: ")
            password = input("Digite sua senha: ")
            login_success = login_user(username, password, sid)

            if login_success:
                main_menu(username)
                break  # Sai do loop após o login bem-sucedido
            else:
                print("\nFalha no login. Tente novamente.")  # Mensagem de erro ao falhar no login
        else:
            print("Opção Invalida!")

    # Desconectar do servidor
    sio.disconnect()


if __name__ == '__main__':
    run_chat()