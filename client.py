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
session_key = None  # Variável global para a chave de sessão


# Funções auxiliares de criptografia

def generate_keypair():
    private_key = RSA.generate(RSA_KEY_SIZE)
    public_key = private_key.publickey()
    return private_key.export_key(), public_key.export_key()


def encrypt_private_key(private_key, password):
    salt = os.urandom(16)
    key = pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(private_key)
    return b64encode(salt + cipher.nonce + tag + ciphertext).decode()


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

def register(username, password):
    private_key, public_key = generate_keypair()
    encrypted_private_key = encrypt_private_key(private_key, password)

    response = requests.post('http://localhost:5000/register', json={
        'username': username,
        'password': password,
        'public_key': public_key.decode()
    })

    print('Status Code:', response.status_code)
    print('Response Text:', response.text)


def login(username, password):
    response = requests.post('http://localhost:5000/login', json={
        'username': username,
        'password': password
    })
    return response.json()


# Iniciar sessão entre dois usuários

def start_session(username_a, username_b):
    response = requests.post('http://localhost:5000/start_session', json={
        'username_a': username_a,
        'username_b': username_b
    })
    return response.json()


# Enviar mensagem criptografada para outro usuário

def send_message(username_a, username_b, message):
    global session_key
    if session_key:
        encrypted_message = encrypt_message(message, session_key)
        response = requests.post('http://localhost:5000/send_message', json={
            'username_a': username_a,
            'username_b': username_b,
            'message': encrypted_message
        })
        print('Send Message Response:', response.json())
    else:
        print("Session key not established. Unable to send message.")


# Lidar com mensagens recebidas

@sio.on('receive_message')
def handle_receive_message(data):
    encrypted_message = data['message']
    message = decrypt_message(encrypted_message, session_key)  # Descriptografa a mensagem
    print(f"Mensagem recebida: {message}")


# Função principal de execução do cliente

def run_client():
    global session_key
    print("Bem-vindo! Escolha uma das opções:")

    # Conectando ao servidor SocketIO
    sio.connect('http://localhost:5000')

    while True:
        print("\n1. Registrar\n2. Login\n3. Iniciar sessão\n4. Enviar mensagem\n5. Sair")
        choice = input("Escolha uma opção: ")

        if choice == '1':
            username = input("Digite o nome de usuário: ")
            password = input("Digite a senha: ")
            register(username, password)

        elif choice == '2':
            username = input("Digite o nome de usuário: ")
            password = input("Digite a senha: ")
            login_response = login(username, password)
            if login_response.get("message") == "Login successful":
                print("Login bem-sucedido!")

        elif choice == '3':
            username_a = input("Seu nome de usuário: ")
            username_b = input("Nome de usuário do destinatário: ")
            session_response = start_session(username_a, username_b)
            if 'key' in session_response:
                session_key = b64decode(session_response['key'])
                print("Sessão iniciada com sucesso!")

        elif choice == '4':
            if session_key:
                username_a = input("Seu nome de usuário: ")
                username_b = input("Nome de usuário do destinatário: ")
                message = input("Digite a mensagem para enviar: ")
                send_message(username_a, username_b, message)
            else:
                print("Sessão não estabelecida. Por favor, inicie uma sessão primeiro.")

        elif choice == '5':
            print("Saindo...")
            break

        else:
            print("Opção inválida. Tente novamente.")


if __name__ == '__main__':
    run_client()
