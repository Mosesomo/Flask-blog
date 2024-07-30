#!/usr/bin/python3
from flaskblog import db, login_manager, serial
from datetime import datetime
from flask_login import UserMixin


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    image = db.Column(db.String(20), nullable=False, default='image.jpg')
    password = db.Column(db.String(20), nullable=False)
    google_id = db.Column(db.String(30), unique=True, nullable=True)
    posts = db.relationship('Post', backref='author', lazy=True)

    @staticmethod
    def very_reset_token(token):
        try:
            email = serial.loads(token, salt='password-reset', max_age=3600)
        except:
            return None
        return User.query.filter_by(email=email).first()

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image}')"


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False,
                            default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.title}', '{self.date_posted}')"
