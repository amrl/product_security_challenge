from . import db
from .models import User
from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, request, flash, make_response
from flask_login import login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import secrets


auth = Blueprint("auth", __name__)


@auth.route("/", methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        remember = request.form.get("remember")

        user = User.query.filter_by(username=username).first()
        current_time = int(datetime.now().timestamp())

        if user and int(user.tries) >= 3 and current_time - int(user.last_access) < 30:
            flash("Account lockout. Try again in a while.")
            return redirect(url_for("auth.login"))

        if user and current_time - int(user.last_access) >= 30:
            user.tries = 0
            db.session.commit()

        if user and not check_password_hash(user.password, password):
            flash("Error: Incorrect username or password.")
            user.last_access = current_time
            user.tries = int(user.tries) + 1
            db.session.commit()
            return redirect(url_for("auth.login"))

        if not user:
            flash("Error: Incorrect username or password.")
            return redirect(url_for("auth.login"))

        user.tries = 0
        db.session.commit()

        login_user(user, remember=remember)

        resp = make_response(redirect(url_for("user.account")))
        resp.set_cookie("cookie", secrets.token_hex(32))
        return resp

    return render_template("index.html")


@auth.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")

        if User.query.filter_by(username=username).first():
            flash("Error: Username is already registered.")
            return redirect(url_for("auth.signup"))

        if User.query.filter_by(email=email).first():
            flash("Error: Email is already registered.")
            return redirect(url_for("auth.signup"))

        if password1 != password2:
            flash("Error: Password confirmation failed.")
            return redirect(url_for("auth.signup"))

        new_user = User(username=username,
                        email=email,
                        password=generate_password_hash(password2, method="sha256"),
                        last_access=int(datetime.now().timestamp()),
                        tries=0)

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for("auth.login"))

    return render_template("signup.html")


@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


def sanitize(input):
    pass


def validate(input):
    pass
