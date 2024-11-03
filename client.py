import os
import json
import requests
import socketio
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
from hashlib import pbkdf2_hmac
import random


# Inicializando o cliente SocketIO
sio = socketio.Client()
RSA_KEY_SIZE = 2048
session_key = None

# Funções auxiliares de criptografia
def generate_keypair():
    private_key = RSA.generate(RSA_KEY_SIZE)
    public_key = private_key.publickey()
    return private_key.export_key(), public_key.export_key()

def encrypt_message(message, session_key):
    cipher = AES.new(session_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt_message(encrypted_message, session_key):
    raw = b64decode(encrypted_message)
    nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# Funções de API para registro e login
def register_user(username, password):
    private_key, public_key = generate_keypair()
    response = requests.post('http://localhost:5000/register', json={
        'username': username,
        'password': password,
        'public_key': public_key.decode()
    })
    print('Status de Registro:', response.status_code)
    return response.ok



def add_user_in_friendlist(username, username_to_add):
    response = requests.post('http://localhost:5000/user', json={
        'username': username,
        'username_to_add': username_to_add
    })
    if response.ok:
        print("Usuario adicionado com sucesso")
    else:
        print("Usuario nao encontrado")


def is_user_in_friendlist(username, username_to_talk):
    response = requests.post('http://localhost:5000/frienlist', json={
        'username': username,
        'username_to_talk': username_to_talk
    })
    if response.ok:
        return True
    return False

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



def login_user(username, password, sid):
    response = requests.post('http://localhost:5000/login', json={
        'username': username,
        'password': password,
        'sid': sid,
    })
    if response.ok:
        print("Login bem-sucedido!")
        return True
    print("Falha no login.")
    return False

# Função principal para execução do chat
def run_chat():
    # Conectar ao servidor SocketIO
    sid = str(random.getrandbits(128))
    sio.connect('http://localhost:5000/login', headers={'sid': sid})

    print("Deseja logar (l) ou se registrar (r)")
    option = input()
    if option == "r":
        username = input("Digite seu nome de usuário: ")
        password = input("Digite sua senha: ")
        register_user(username, password)
    if option == "l":
        username = input("Digite seu nome de usuário: ")
        password = input("Digite sua senha: ")
        login_success = login_user(username, password, sid)

        if not login_success:
            return

        print("Voce deseja:"
              "\n1 - Adicionar um usuario\n"
              "\n2 - Conversar com um usuario na sua lista de amigos\n")
        choice = int(input("Digite sua opcao: "))

        if choice == 1:
            user_to_add = input("Digite o nome do usuario: ")
            add_user_in_friendlist(username, user_to_add)
        if choice == 2:
            user_to_talk = input("Digite o nome do usuario da lista de amigos que voce quer conversar: ")
            if not is_user_in_friendlist(username, user_to_talk):
                return

            # Iniciar sessão de comunicação
            start_session(username, user_to_talk)

            # Esperar pela confirmação da sessão antes de enviar mensagens
            print("Envie suas mensagens. Digite 'sair' para encerrar.")
            while True:
                message = input("Você: ")
                if message.lower() == "sair":
                    print("Encerrando o chat.")
                    break
                send_message(username, user_to_talk, message)
    # Desconectar do servidor
    sio.disconnect()

if __name__ == '__main__':
    run_chat()