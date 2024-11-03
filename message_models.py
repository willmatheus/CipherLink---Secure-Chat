from datetime import datetime, timedelta
from config import *


class Message(db.Model):
    tablename = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Remetente
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Destinatário
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    duration = db.Column(db.Interval, nullable=False, default=timedelta(seconds=50))  # Duração padrão de 7 dias

    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_messages')

    def repr(self):
        return f'<Message {self.id} from User {self.sender_id} to User {self.recipient_id}>'