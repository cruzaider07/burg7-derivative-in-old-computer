# ty 

from flask import render_template, request, Blueprint, session, redirect, url_for
from .models import Message, Item, User
from flask_login import current_user
from . import db 

views = Blueprint('views', __name__)

@views.route('/')
def home():
    return render_template('home.html', user=current_user)

@views.route('contact', methods=['GET','POST'])
def contact(): 
    if request.method == 'POST':
        name = request.form['name']
        message = request.form['textarea']

        session['name'] = name 
        session['textarea'] = message

        new_message = Message(name=name, message=message)
        db.session.add(new_message)
        db.session.commit()

    return render_template('contact.html', user=current_user)

@views.route('/review')
def review():
 
    max_id_query = Message.query.with_entities(Message.owner).order_by(Message.owner.desc()).first()
    message_with_max_id = Message.query.order_by(Message.owner.desc()).first()

    before_max_id = max_id_query[-1] - 1
    before_message_with_max_id = Message.query.filter_by(id=before_max_id).first()

    return render_template('review.html', user=current_user, name=session['name'], message=session['textarea'], max_id_query=max_id_query, before_max_id=before_max_id, before_message_with_max_id=before_message_with_max_id)

@views.route('/about')
def about(): 
    return render_template('about.html', user=current_user)

@views.route('/menu', methods=['GET','POST'])
def menu():
    if request.method == 'POST':
        qty_no = request.form['qty_no']

        if qty_no == '':
            qty_no = 0

        qty_no1 = request.form['qty_no1']

        if qty_no1 == '':
            qty_no1 = 0

        qty_no2 = request.form['qty_no2']

        if qty_no2 == '':
            qty_no2 = 0

        qty_no = int(qty_no)
        qty_no1 = int(qty_no1)
        qty_no2 = int(qty_no2)

        session['qty_no'] = qty_no
        session['qty_no1'] = qty_no1
        session['qty_no2'] = qty_no2
        
        burger = Item(name='Meaty-Cheezy Burger')
        burger1 = Item(name='Bacon-Layered Burger')
        burger2 = Item(name='Crispy-Layered Burger')

        for i in range(qty_no):

            db.session.add(Item(name='Meaty-Cheezy Burger'))
            db.session.commit()

        for i in range(qty_no1):

            db.session.add(Item(name='Bacon-Layered Burger'))
            db.session.commit()

        for i in range(qty_no2):

            db.session.add(Item(name='Crispy-Layered Burger'))
            db.session.commit()


        session['burger2'] = burger2.name
        session['burger1'] = burger1.name
        session['burger'] = burger.name

        if not current_user.is_authenticated: 
            return redirect(url_for('auth.login'))
        else:
            return redirect(url_for('views.ordered'))
        
    return render_template('menu.html', user=current_user)

@views.route('/menu/ordered')
def ordered():
    return render_template('ordered.html', qty_no=session['qty_no'], qty_no1=session['qty_no1'], qty_no2=session['qty_no2'], burger=session['burger'], burger1=session['burger1'], burger2=session['burger2'], user=current_user)