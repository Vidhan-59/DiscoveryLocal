import mongoengine as me
from datetime import datetime, timedelta

class User(me.Document):
    username = me.StringField(required=True, unique=True, max_length=100)
    email = me.EmailField(required=True, unique=True)
    password = me.StringField(required=True)
    contact_number = me.StringField(required=True, max_length=15)
    state = me.StringField(required=True, max_length=100)

    meta = {
        'collection': 'users',
        'indexes': [
            'username',
            'email',
        ]
    }

class Token(me.Document):
    user = me.ReferenceField(User, required=True)
    key = me.StringField(required=True, unique=True)
    created_at = me.DateTimeField(default=datetime.utcnow)
    expires_at = me.DateTimeField(default=lambda: datetime.utcnow() + timedelta(days=7))  # Token valid for 7 days by default

    meta = {
        'collection': 'tokens',
    }

    def is_valid(self):
        return self.expires_at > datetime.utcnow() if self.expires_at else True

import mongoengine as me
from datetime import datetime, timedelta

class OTP(me.Document):
    email = me.EmailField(required=True)
    otp = me.StringField(required=True)
    created_at = me.DateTimeField(default=datetime.utcnow)
    expires_at = me.DateTimeField(default=lambda: datetime.utcnow() + timedelta(minutes=5))

    meta = {
        'collection': 'otps',
        'indexes': ['email', 'otp', 'expires_at'],
    }

    def is_expired(self):
        return self.expires_at < datetime.utcnow()
