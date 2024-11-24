from werkzeug.security import generate_password_hash, check_password_hash
from config import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    # Campo para armazenar os amigos como uma string delimitada por vírgula
    friend_list = db.Column(db.Text, default='')

    def get_user_id(self):
        return self.id

    def get_username(self):
        return self.username

    def get_password_hashed(self):
        return self.password_hash

    def get_public_key(self):
        return self.public_key

    def get_friend_list(self):
        # Converte a string em uma lista ao recuperar
        return self.friend_list.split(',') if self.friend_list else []

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def add_user_to_friendlist(self, username):
        # Adiciona um amigo somente se não estiver na lista
        friends = self.get_friend_list()
        if username not in friends:
            friends.append(username)
            self.friend_list = ','.join(friends)  # Converte a lista para string

    def is_user_in_friendlist(self, username):
        return username in self.get_friend_list()
