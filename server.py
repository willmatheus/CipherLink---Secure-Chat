import base64
import os
from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, emit
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from user_models import User, db
from Crypto.Random import get_random_bytes

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://karolyneraq:1234@localhost/meubanco'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
migrate = Migrate(app, db)
socketio = SocketIO(app)

# Armazenamento de sessões
sessions = {}

@app.route('/login_auth')
def login_page():
    return render_template('login.html')

@app.route('/chat')
def chat_page():
    return render_template('chat.html')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    password = data['password']
    public_key = data['public_key']

    password_hash = generate_password_hash(password)
    user = User(username=username, password_hash=password_hash, public_key=public_key)
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.get_password_hashed(), password):
        return jsonify({'message': 'Login successful', 'username': username}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

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

    # Recupera a chave pública de B
    user_b = User.query.filter_by(username=username_b).first()
    if user_b:
        # Gera uma chave de sessão simétrica
        session_key = get_random_bytes(32)
        sessions[(username_a, username_b)] = session_key
        sessions[(username_b, username_a)] = session_key  # Ambas as direções
        emit('session_started', {'message': 'Session started', 'key': base64.b64encode(session_key).decode()}, room=username_a)
        emit('session_started', {'message': 'Session started', 'key': base64.b64encode(session_key).decode()}, room=username_b)

@socketio.on('send_message')
def handle_send_message(data):
    encrypted_message = data['message']
    username_a = data['username_a']
    username_b = data['username_b']

    # Recupera a chave de sessão
    session_key = sessions.get((username_a, username_b))

    if session_key:
        # Envia a mensagem criptografada para o destinatário
        emit('receive_message', {'message': encrypted_message}, room=username_b)
    else:
        print(f"Session not found for {username_a} and {username_b}.")

if __name__ == '__main__':
    socketio.run(app, debug=True)
