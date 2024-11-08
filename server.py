import base64
import os
from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from user_models import User
from message_models import Message
from Crypto.Random import get_random_bytes
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from apscheduler.schedulers.background import BackgroundScheduler
from config import *

load_dotenv()

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
migrate = Migrate(app, db)
socketio = SocketIO(app)

# Armazenamento de sessões
sessions = {}
clients = {}

# FUNCTIONS FOR TEST ####################################
def add_message(sender_id, recipient_id, content, duration_seconds=40):
    with app.app_context():
        new_message = Message(
            sender_id=sender_id,
            recipient_id=recipient_id,
            content=content,
            duration=timedelta(seconds=duration_seconds)  # Duração da mensagem
        )
        db.session.add(new_message)
        db.session.commit()


def add_user(username, password_hash, public_key):
    with app.app_context():
        new_user = User(username=username, password_hash=password_hash, public_key=public_key)
        db.session.add(new_user)
        db.session.commit()
        return new_user.id
######################################################


def clean_expired_messages():
    with app.app_context():
        now = datetime.now(timezone.utc)

        expired_messages = Message.query.filter(
            (now - Message.timestamp) > Message.duration
        ).all()

        for message in expired_messages:
            db.session.delete(message)

        db.session.commit()


# ---------- User Authentication Routes -------------

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    password = data['password']
    public_key = data['public_key']
    password_hash = generate_password_hash(password)
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'User already exists'}), 401
    user = User(username=username, password_hash=password_hash, public_key=public_key)
    db.session.add(user)
    db.session.commit()
    print(f"\nDEBUG: Chave publica: {public_key}")
    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']
    sid = request.json['sid']

    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.get_password_hashed(), password):
        clients[sid] = username

        offline_messages = update_offline_messages(user.id)

        print(clients)
        return jsonify({'message': 'Login successful', 'username': username,'offline_messages': offline_messages}), 200

    return jsonify({'message': 'Invalid credentials'}), 401


# ---------- Chat Functions -------------

def update_offline_messages(sender_id):
    msgs = Message.query.filter_by(sender_id=sender_id).values()
    return [msg.to_dict() for msg in msgs]


@socketio.on('connect')
def handle_connect():
    sid = request.headers['sid']
    print(f"User connected with session id: {sid}")


@socketio.on('disconnect')
def handle_disconnect():
    sid = request.headers['sid']
    if sid in clients:
        del clients[sid]  # Remove o cliente da lista ao desconectar

    print(f"User with session id {sid} disconnected.")
    print(clients)


# ---------- User Routes -------------

@app.route('/user', methods=['POST'])
def add_user_in_friendlist():
    username = request.json['username']
    user_name_to_add = request.json['username_to_add']
    user = User.query.filter_by(username=username).first()
    user_name_to_add = User.query.filter_by(username=user_name_to_add).first().get_username()
    if user_name_to_add:
        user.add_user_to_friendlist(user_name_to_add)
        db.session.commit()
        return jsonify({'message': 'User successfully added', 'User added': user_name_to_add}), 200
    return jsonify({'message': 'User not founded'}), 401


@app.route('/all_users', methods=['GET'])
def get_all_users():
    users = User.query.all()
    all_usernames = [user.username for user in users]
    return jsonify({"users": all_usernames}), 200

# ---------- Friendlist Routes -------------

@app.route('/frienlist', methods=['POST'])
def is_user_in_friendlist():
    username = request.json['username']
    username_to_talk = request.json['username_to_talk']
    user_friend_list = User.query.filter_by(username=username).first().get_friend_list()
    if username_to_talk in user_friend_list:
        return jsonify({'status': True}), 200
    return jsonify({'message': 'User not found'}), 404


@app.route('/friendlist/<username>', methods=['GET'])
def get_friend_list(username):
    user = User.query.filter_by(username=username).first()
    if user:
        friend_list = user.get_friend_list()
        return jsonify({"friends": friend_list}), 200
    return jsonify({"message": "User not found"}), 404


@app.route('/get_public_key/<username>', methods=['GET'])
def get_public_key(username):
    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({'public_key': user.public_key}), 200
    return jsonify({'message': 'User not found'}), 404


@socketio.on('start_session')
def handle_start_session(data):
    username_a = data['username_a']
    username_b = data['username_b']

    # Verifica se os usuários existem
    user_a = User.query.filter_by(username=username_a).first()
    user_b = User.query.filter_by(username=username_b).first()

    if not user_a or not user_b:
        emit('error', {'message': 'Um ou ambos os usuários não existem.'}, room=request.sid)
        return

    # Gera uma chave de sessão simétrica
    session_key = get_random_bytes(32)
    print(f"DEBUG: Chave de sessão: {session_key}")
    sessions[(username_a, username_b)] = session_key
    sessions[(username_b, username_a)] = session_key  # Ambas as direções

    # Adiciona os usuários ao "room"
    join_room(username_a)
    join_room(username_b)

    # Envia a chave de sessão criptografada para ambos os usuários
    emit('session_started', {'message': 'Session started', 'key': base64.b64encode(session_key).decode()}, room=username_a)
    emit('session_started', {'message': 'Session started', 'key': base64.b64encode(session_key).decode()}, room=username_b)


@socketio.on('send_message')
def handle_send_message(data):
    encrypted_message = data['message']
    username_a = data['username_a']
    username_b = data['username_b']

    # Recupera a chave de sessão para verificar se a sessão está ativa
    session_key = sessions.get((username_a, username_b))

    is_user_b_online = username_b in clients.values()

    if True:
        if is_user_b_online:
            # Envia a mensagem criptografada diretamente ao destinatário no "room"
            emit('receive_message', {'message': encrypted_message}, room=username_b)
        else:
            add_message(1, 2, encrypted_message)

    else:
        print(f"Session not found for {username_a} and {username_b}.")
        emit('error', {'message': 'Sessão não encontrada. Por favor, inicie uma nova sessão.'}, room=username_a)


scheduler = BackgroundScheduler()
scheduler.add_job(func=clean_expired_messages, trigger="interval", seconds=20)  # Limpa a cada 20 segundos
scheduler.start()

if __name__ == '__main__':
    # with app.app_context():
       # add_message(sender_id=1, recipient_id=2, content="nois eh viado porra teste")

    socketio.run(app, debug=True)

    #socketio.run(app, host='0.0.0.0', port=5000, debug=True)
