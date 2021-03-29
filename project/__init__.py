from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from os import path
from secrets import token_hex


DATABASE = "accounts.db"
db = SQLAlchemy()
csrf = CSRFProtect()


def create_app():
    app = Flask(__name__)

    app.config["SECRET_KEY"] = token_hex(32)
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + DATABASE
    csrf.init_app(app)

    db.init_app(app)

    from .auth import auth
    app.register_blueprint(auth)

    from .user import user
    app.register_blueprint(user)

    from .models import User

    if not path.exists("project/" + DATABASE):
        db.create_all(app=app)

    login_manager = LoginManager()
    login_manager.login_view = "auth.login"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    return app
