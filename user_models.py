from werkzeug.security import generate_password_hash, check_password_hash
from config import *


class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    friend_list = db.Column(db.PickleType, default=[])

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_password_hashed(self):
        return self.password_hash