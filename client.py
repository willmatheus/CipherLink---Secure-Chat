import os
import json
import requests
import socketio
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
from hashlib import pbkdf2_hmac

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

def login_user(username, password):
    response = requests.post('http://localhost:5000/login', json={
        'username': username,
        'password': password
    })
    if response.ok:
        print("Login bem-sucedido!")
        return True
    print("Falha no login.")
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

# Função principal para execução do chat
def run_chat():
    # Conectar ao servidor SocketIO
    sio.connect('http://localhost:5000')

    # Solicitar credenciais
    username = input("Digite seu nome de usuário: ")
    password = input("Digite sua senha: ")

    # Registrar ou logar usuário
    if not register_user(username, password):
        login_success = login_user(username, password)
        if not login_success:
            print("Não foi possível fazer login.")
            return

    # Solicitar nome de usuário do destinatário
    recipient = input("Digite o nome de usuário do destinatário: ")

    # Iniciar sessão de comunicação
    start_session(username, recipient)

    # Esperar pela confirmação da sessão antes de enviar mensagens
    print("Envie suas mensagens. Digite 'sair' para encerrar.")
    while True:
        message = input("Você: ")
        if message.lower() == "sair":
            print("Encerrando o chat.")
            break
        send_message(username, recipient, message)

    # Desconectar do servidor
    sio.disconnect()

if __name__ == '__main__':
    run_chat()
