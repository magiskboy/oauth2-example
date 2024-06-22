import os

ROOT_DIR = os.getcwd()

DEBUG = os.getenv("DEBUG", True)

SQLALCHEMY_DATABASE_URI = os.getenv(
    "SQLALCHEMY_DATABASE_URI", "sqlite:///" + os.path.join(ROOT_DIR, "db.sqlite3")
)

SECRET_KEY = 'secrets.token_urlsafe(32)'

JWT_PRIVATE_KEY = os.getenv(
    "JWT_PRIVATE_KEY", os.path.join(ROOT_DIR, "keys", "private.pem")
)
JWT_PUBLIC_KEY = os.getenv(
    "JWT_PUBLIC_KEY", os.path.join(ROOT_DIR, "keys", "public.pem")
)

ISSUER = os.getenv("ISSUER", "http://authorization-server.local")
