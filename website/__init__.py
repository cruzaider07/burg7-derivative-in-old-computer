# ty
# load_ will not sense the load_user in other window

from flask import Flask 
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()
db_name = 'database.db'

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'key'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_name}'
    db.init_app(app)

    from .auth import auth
    from .views import views

    app.register_blueprint(auth, url_prefix='/')
    app.register_blueprint(views, url_prefix='/')

    from .models import User, Item

    with app.app_context():
        db.create_all()

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))
    
    return app
