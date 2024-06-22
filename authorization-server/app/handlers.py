from flask import (
    request,
    session,
    redirect,
    url_for,
    render_template,
    jsonify,
    flash,
    abort,
)
from sqlalchemy.exc import IntegrityError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode
from . import models, utils


def create_application():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login", next=request.url))

    if request.method == "POST":
        name = request.form.get("name")
        description = request.form.get("description")
        redirect_uris = request.form.get("redirect_uris")

        if not (name and redirect_uris):
            flash("All fields are required")
            return redirect(url_for("create_application"))

        user = models.User.query.get(user_id)
        application = models.Application.create(
            name=name,
            description=description,
            redirect_uris=redirect_uris.split(",") if redirect_uris else [],
            user=user,
        )
        application.save()

        flash(f"Application {application.name} was created successfully")
        return redirect(url_for("application"))

    return render_template("create_application.html")


def application():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login", next=request.url))

    applications = models.Application.query.filter_by(user_id=user_id).all()
    return render_template("application.html", applications=applications)


def register():
    if session.get("user_id"):
        return redirect(url_for("index"))

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if not (email and password and confirm_password):
            flash("All fields are required")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match")
            return redirect(url_for("register"))

        try:
            user = models.User(email=email)
            user.set_password(password)
            user.save()
        except IntegrityError:
            flash("User already exists")
            return redirect(url_for("register"))

        return redirect(url_for("login"))

    return render_template("register.html")


def index():
    user_id = session.get("user_id")
    if not user_id:
        flash("Please login to access this page")
        return redirect(url_for("login", next=request.url))

    user = models.User.query.get(user_id)

    return render_template("index.html", user=user)


def login():
    if session.get("user_id"):
        return jsonify({"message": "Already logged in"})

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if not (email and password):
            flash("All fields are required")
            return redirect(url_for("login"))

        user = models.User.query.filter_by(email=email).first()
        if not user:
            flash("User not found")
            return redirect(url_for("login"))

        if not user.verify_password(password):
            flash("Incorrect password")
            return redirect(url_for("login"))

        session["user_id"] = user.id

        if "next" in request.args:
            return redirect(request.args.get("next"))

        return redirect(url_for("index"))

    return render_template("login.html")


def logout():
    session.pop("user_id", None)
    return redirect(url_for("login"))


def authorize():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login", next=request.url))

    client_id = request.args.get("client_id")
    client_secret = request.args.get("client_secret")
    redirect_uri = request.args.get("redirect_uri")
    scopes = request.args.get("scopes")

    if not (client_id and client_secret and redirect_uri and scopes):
        abort(400, description="All fields are required")

    application = models.Application.query.filter_by(client_id=client_id).first()
    if not application:
        abort(400, description="Application not found")

    if not application.verify_client_secret(client_secret):
        abort(400, description="Invalid client secret")

    if redirect_uri not in application.get_redirect_uris():
        abort(400, description=f"Invalid redirect URI {redirect_uri}")

    if request.method == "POST":
        response = request.form.get("response")

        if response == "accept":
            user = models.User.query.get(user_id)
            authorization_code = models.AuthorizationCode.create(
                user=user,
                application=application,
                redirect_uri=redirect_uri,
            )
            return redirect(f"{redirect_uri}?code={authorization_code.code}")

        else:
            return redirect(f"{redirect_uri}?error=access_denied")

    return render_template("authorize.html")


def get_access_token():
    data = request.json
    grant_type = data.get("grant_type")
    client_id = data.get("client_id")
    client_secret = data.get("client_secret")
    redirect_uri = data.get("redirect_uri")
    code = data.get("code")

    if not (grant_type and client_id and client_secret and redirect_uri and code):
        abort(400, description="All fields are required")

    if grant_type != "authorization_code":
        abort(400, description="Invalid grant type")

    application = models.Application.query.filter_by(client_id=client_id).first()
    if not application:
        abort(400, description="Application not found")

    if not application.verify_client_secret(client_secret):
        abort(400, description="Invalid client secret")

    authorization_code = models.AuthorizationCode.query.filter_by(code=code).first()
    if not authorization_code:
        abort(400, description="Authorization code not found")

    if not authorization_code.is_valid():
        abort(400, description="Authorization code is expired")

    if authorization_code.application_id != application.id:
        abort(400, description="Invalid application")

    access_token, refresh_token = utils.generate_token(
        user=authorization_code.user,
        scopes=["opendid", "profile", "email"],
        application=application,
    )

    return jsonify({"access_token": access_token, "refresh_token": refresh_token})


def well_known():
    applications = models.Application.query.all()
    keys = []

    for application in applications:
        public_key = serialization.load_pem_public_key(
            application.public_key_pem.encode("utf-8"), backend=default_backend()
        )
        n = public_key.public_numbers().n
        e = public_key.public_numbers().e
        keys.append(
            {
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": application.client_id,
                "n": int_to_base64url(n),
                "e": int_to_base64url(e),
            }
        )

    return jsonify(
        {
            "keys": keys,
        }
    )


def int_to_base64url(n):
    # Convert integer to bytes, base64url encode, then decode to string
    return (
        urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big"))
        .decode("utf-8")
        .rstrip("=")
    )
