# ty 

from flask_login import UserMixin 
from . import db  

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(20))
    lname = db.Column(db.String(20))
    email = db.Column(db.String(20))
    pword = db.Column(db.String(20))
    messages = db.relationship('Message', lazy=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(10))
    message = db.Column(db.String(100))
    owner = db.Column(db.Integer, db.ForeignKey('user.id'))

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(39))
    