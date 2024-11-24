from config import db


class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_name = db.Column(db.String(80), nullable=False)
    session_key = db.Column(db.Text, unique=True, nullable=False)

    def get_user_id(self):
        return self.user_id

    def get_session_key(self):
        return self.session_key
