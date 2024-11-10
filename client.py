import requests
import socketio
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from utils import *

# Inicializando o cliente SocketIO
sio = socketio.Client()
RSA_KEY_SIZE = 2048
session_key = None

# ---------- Cryptography auxiliary functions -------------
message_history = []
global global_private_key
session_keys = {}

def generate_keypair():
    private_key = RSA.generate(RSA_KEY_SIZE)
    public_key = private_key.publickey()
    return private_key.export_key(), public_key.export_key()

# ---------- Friendlist Functions -------------
def add_user_in_friendlist(username, username_to_add):
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


def request_user_public_key(username_to_talk):
    sio.emit('handle_public_key_request', {'username_to_talk': username_to_talk})


def join_room(username, username_to_talk):
    sio.emit('join', {'username': username, 'username_to_talk': username_to_talk})

@sio.on('receive_public_key')
def handle_receive_public_key(data):
    username_to_talk = data['username_to_talk']
    user_public_key = data['user_public_key']
    session_key = get_random_bytes(32)
    encrypted_session_key = encrypt_with_public_key(session_key, user_public_key)

    sio.emit('send_session_key', {
        'username_to_talk': username_to_talk,
        'encrypted_session_key': encrypted_session_key
    })
    session_keys[username_to_talk] = session_key


# Callback para recebimento da chave de sessão
@sio.on('receive_session_key')
def on_receive_session_key(data):
    print("on_receive_session_key")
    encrypted_session_key = data['encrypted_session_key']
    username_to_talk = data['username_to_talk']
    session_key = decrypt_with_private_key(encrypted_session_key, global_private_key)
    if not session_keys:
        print("No session key !!!!!!!!!")
        return
    session_keys[username_to_talk] = session_key
    print(session_keys)


def send_message(username_to_talk, message):


    # Envia a mensagem criptografada
    sio.emit('send_message', {
        'username_to_talk': username_to_talk,
        'encrypted_message': message
    })


# Callback para recebimento de mensagem
@sio.on('receive_message')
def on_receive_message(data):
    encrypted_message = data['encrypted_message']
    username_to_talk = data['username_to_talk']
    print(f"{username_to_talk}:", encrypted_message)


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
    global global_private_key
    global_private_key = private_key

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


def login_user(username, password):
    response = requests.post('http://localhost:5000/login', json={
        'username': username,
        'password': password,
    })

    if response.ok:
        private_key_encrypted = recover_private_key(username)
        private_key = decrypt_private_key(private_key_encrypted, password)

        print("DEBUG: Chave privada recuperada")
        print("\nLogin bem-sucedido!")
        print("Mensagens offline:", response.json().get('offline_messages', []))
        global global_private_key
        global_private_key = private_key
        return True, private_key

    print("\nFalha no login.")
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
        send_message(user_to_talk, message)


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

            join_room(username, user_to_talk)

            chat_with_user(username, user_to_talk)
        elif choice == "3":
            print("Encerrando o programa. Ate logo!")
            break
        else:
            print("Opcao Invalida!")


# Função principal para execução do chat
def run_chat():

    sio.connect('http://localhost:5000/')
    #sio.connect('http://192.168.1.7:5000', headers={'sid': sid})

    print("\n")

    print(
        "      ...             .                                                               ...         .                        ..    ")
    print(
        "      ...             .                                                               ...         .                        ..     ")
    print(
        '   xH88"`~ .x8X      @88>                  .uef^"                                 .zf"` `"tu     @88>                < .z@8"`      ')
    print(
        """ :8888   .f"8888Hf   %8P    .d``         :d88E                     .u    .       x88      '8N.   %8P      u.    u.    !@88E        """)
    print(
        ":8888>  X8L  ^""`     .      @8Ne.   .u   `888E            .u     .d88B :@8c      888k     d88&    .     x@88k u@88c.  '888E   u ")
    print(
        """X8888  X888h        .@88u   %8888:u@88N   888E .z8k    ud8888.  ="8888f8888r     8888N.  @888F  .@88u  ^"8888""8888"   888E u@8NL  """)
    print(
        """88888  !88888.     ''888E`   `888I  888.  888E~?888L :888'8888.   4888>'88"      `88888 9888%  ''888E`   8888  888R    888E`"88*"  """)
    print(
        """88888   %88888       888E     888I  888I  888E  888E d888 '88%"   4888> '          %888 "88F     888E    8888  888R    888E .dN.   """)
    print(
        """88888 '> `8888>      888E     888I  888I  888E  888E 8888.+"      4888>             8"   "*h=~   888E    8888  888R    888E~8888   """)
    print(
        "`8888L %  ?888   !   888E   uW888L  888'  888E  888E 8888L       .d888L .+        z8Weu          888E    8888  888R    888E '888&  ")
    print(
        """ `8888  `-*""   /    888&  '*88888Nu88P   888E  888E '8888c. .+  ^"8888*"        ""88888i.   Z   888&   "*88*" 8888"   888E  9888. """)
    print(
        """   "888.      :"     R888" ~ '88888F`    m888N= 888>  "88888%       "Y"         "   "8888888*    R888"    ""   'Y"   '"888*" 4888" """)
    print(
        """     `""***~"`        ""      888 ^       `Y"   888     "YP'                          ^"**""      ""                    ""    ""   """)
    print(
        """                              *8E              J88"                                                                                """)
    print(
        """                              '8>              @%                                                                                  """)
    print(
        """                               "             :"                                                                                    """)

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
            login_success, private_key = login_user(username, password)

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
