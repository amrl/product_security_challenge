from . import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True)
    email = db.Column(db.String(512), unique=True)
    password = db.Column(db.String(256))
    tries = db.Column(db.Integer)
    last_access = db.Column(db.Integer)
