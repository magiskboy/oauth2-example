from base64 import urlsafe_b64encode
from datetime import datetime, timedelta
from flask import current_app
import jwt
from . import models


def generate_token(user, scopes, application):
    ISSUER = current_app.config.get("ISSUER")
    claim = {
        "sub": str(user.id),
        "email": user.email,
        "scopes": scopes,
        "exp": datetime.utcnow() + timedelta(minutes=15),
        "iss": ISSUER,
    }

    access_token = jwt.encode(claim, key=application.private_key_pem, algorithm="RS256")
    refresh_token = jwt.encode(
        {
            "sub": str(user.id),
            "client_id": application.client_id,
            "scopes": scopes,
            "exp": datetime.utcnow() + timedelta(days=7),
            "iss": ISSUER,
        },
        key=application.private_key_pem,
        algorithm="RS256",
    )

    return access_token, refresh_token


def verify_token(token):
    unverified_header = jwt.get_unverified_header(token)
    client_id = unverified_header["kid"]
    application = models.Application.query.filter_by(client_id=client_id).first()
    try:
        payload = jwt.decode(
            token, key=application.public_key_pem, algorithms="RS256", verify=True
        )
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidAudienceError:
        return None
    except jwt.InvalidTokenError:
        return None


def int_to_base64url(n):
    # Convert integer to bytes, base64url encode, then decode to string
    return (
        urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big"))
        .decode("utf-8")
        .rstrip("=")
    )
