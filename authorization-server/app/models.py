import secrets
import uuid
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import UUID
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()
migrate = Migrate()


class BaseModel(db.Model):
    __abstract__ = True

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()


class User(BaseModel):
    __tablename__ = "users"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def __repr__(self):
        return f"<User {self.username}>"


class Application(BaseModel):
    __tablename__ = "applications"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String(120), unique=True, nullable=False)
    description = db.Column(db.String(255))
    client_id = db.Column(db.String(120), unique=True, nullable=False)
    client_secret = db.Column(db.String(120), nullable=False)
    redirect_uris = db.Column(db.String(255), nullable=False)
    private_key_pem = db.Column(db.Text)
    public_key_pem = db.Column(db.Text)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("users.id"), nullable=False)
    user = db.relationship("User", backref=db.backref("applications", lazy=True))

    def get_redirect_uris(self):
        return self.redirect_uris.split(",")

    def set_redirect_uris(self, redirect_uris):
        self.redirect_uris = ",".join(redirect_uris)

    def verify_client_secret(self, client_secret):
        return self.client_secret == client_secret

    def verify_redirect_uri(self, redirect_uri):
        return redirect_uri in self.get_redirect_uris()

    @classmethod
    def create(cls, user, name, description, redirect_uris):
        client_id = secrets.token_urlsafe(32)
        client_secret = secrets.token_urlsafe(32)

        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Generate public key
        public_key = private_key.public_key()

        # Serialize private key
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        # Serialize public key
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        application = cls(
            name=name,
            description=description,
            redirect_uris=",".join(redirect_uris),
            client_id=client_id,
            client_secret=client_secret,
            private_key_pem=private_key_pem,
            public_key_pem=public_key_pem,
            user=user,
        )
        application.save()
        return application

    def __repr__(self):
        return f"<Application {self.name}>"


class AuthorizationCode(BaseModel):
    __tablename__ = "authorization_codes"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    code = db.Column(db.String(120), unique=True, nullable=False)
    redirect_uri = db.Column(db.String(255), nullable=False)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("users.id"), nullable=False)
    user = db.relationship("User", backref=db.backref("authorization_codes", lazy=True))
    application_id = db.Column(
        UUID(as_uuid=True), db.ForeignKey("applications.id"), nullable=False
    )
    application = db.relationship(
        "Application", backref=db.backref("authorization_codes", lazy=True)
    )
    expiration_time = db.Column(db.TIMESTAMP, nullable=False)

    def is_valid(self):
        return self.expiration_time > datetime.now() and self.application

    @classmethod
    def create(cls, user, application, redirect_uri):
        authorization_code = cls(
            code=secrets.token_urlsafe(32),
            redirect_uri=redirect_uri,
            user=user,
            application=application,
            expiration_time=datetime.now() + timedelta(minutes=10),
        )
        authorization_code.save()
        return authorization_code

    def __repr__(self):
        return f"<AuthorizationCode {self.code}>"
