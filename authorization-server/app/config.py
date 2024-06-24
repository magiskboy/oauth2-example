import os
import secrets

ROOT_DIR = os.getcwd()

SQLALCHEMY_DATABASE_URI = os.getenv(
    "SQLALCHEMY_DATABASE_URI", "sqlite:///" + os.path.join(ROOT_DIR, "db.sqlite3")
)

SECRET_KEY = secrets.token_urlsafe(32)

ISSUER = os.getenv("ISSUER", "http://authorization-server.local")
