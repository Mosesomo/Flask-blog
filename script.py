#!/usr/bin/python3
from flaskblog import app, db
from flaskblog.models import User, Post

with app.app_context():
    db.create_all()
    users = User.query.all()
    for user in users:
        print(user)
    post = Post.query.all()
    print(post)
