from . import db
from .models import User
from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, request, flash, make_response
from flask_login import login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import re
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
            flash("Incorrect username or password.")
            user.last_access = current_time
            user.tries = int(user.tries) + 1
            db.session.commit()
            return redirect(url_for("auth.login"))

        if not user:
            flash("Incorrect username or password.")
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
            flash("Username is already registered.")
            return redirect(url_for("auth.signup"))

        if not is_valid_username(username):
            flash("Username can only contain alphanumeric characters and single hyphens in-between. Max length is 39 characters.")
            return redirect(url_for("auth.signup"))

        if User.query.filter_by(email=email).first():
            flash("Email is already registered.")
            return redirect(url_for("auth.signup"))

        if password1 != password2:
            flash("Password confirmation failed.")
            return redirect(url_for("auth.signup"))

        if not is_valid_password(password2):
            flash("Password must be 8 to 64 characters long and contain at least 1 lowercase, 1 uppercase, 1 digit, and 1 special character.")
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


'''
Following GitHub rules:
Contain only alphanumeric chars or hyphens.
Cannot have multiple consecutive hyphens.
Cannot begin or end with a hyphen.
Max length of 39 chars.
'''
def is_valid_username(username):
    return bool(re.match("^[a-zA-Z\d](?:[a-zA-Z\d]|-(?=[a-zA-Z\d])){0,38}$",
                         username))


'''
Following NIST recommendations of minimum 8 characters,
and max to (at least) 64 characters.
At least 1 digit.
At least 1 lowercase letter.
At least 1 uppercase letter.
At least 1 special character.
'''
def is_valid_password(password):
    return bool(re.match("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[*.!@$%^&(){}[\]:;<>,.?\/~_+-=|]).{8,64}$",
                         password))
