from flask import Blueprint, render_template
from flask_login import login_required, current_user


user = Blueprint("user", __name__)


@user.route("/account")
@login_required
def account():
    return render_template("account.html", username=current_user.username, email=current_user.email)
