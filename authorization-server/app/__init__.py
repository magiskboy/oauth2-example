from flask import Flask
from . import models
from . import handlers

def create_app():
    app = Flask(__name__)
    app.config.from_pyfile('config.py')

    models.db.init_app(app)
    models.migrate.init_app(app, models.db)

    app.add_url_rule('/', 'index', handlers.index)
    app.add_url_rule('/create-application', 'create_application', handlers.create_application, methods=['GET', 'POST'])
    app.add_url_rule('/application', 'application', handlers.application)
    app.add_url_rule('/login', 'login', handlers.login, methods=['GET', 'POST'])
    app.add_url_rule('/logout', 'logout', handlers.logout)
    app.add_url_rule('/register', 'register', handlers.register, methods=['GET', 'POST'])
    app.add_url_rule('/authorize', 'authorize', handlers.authorize, methods=['GET', 'POST'])
    app.add_url_rule('/token', 'token', handlers.get_access_token, methods=['POST'])
    app.add_url_rule('/.well-known/jwks.json', 'jwks', handlers.well_known, methods=['GET'])

    return app