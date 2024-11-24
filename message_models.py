from datetime import datetime, timedelta
from config import db


class Message(db.Model):
    __tablename__ = 'message'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Remetente
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Destinatário
    content = db.Column(db.Text, nullable=False)
    room_id = db.Column(db.String(80), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now())
    duration = db.Column(db.Interval, nullable=False, default=lambda: timedelta(seconds=50))  # Duração padrão

    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_messages')

    def to_dict(self):
        return {
            'id': self.id,
            'sender_id': self.sender_id,
            'recipient_id': self.recipient_id,
            'content': self.content,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            # Retornando apenas IDs para evitar problemas de serialização
            'sender_username': self.sender.username if self.sender else None,
            'recipient_username': self.recipient.username if self.recipient else None,
        }

    def get_content(self):
        return self.content

    def __repr__(self):
        return f'<Message {self.id} from User {self.sender_id} to User {self.recipient_id}>'
