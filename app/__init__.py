import os
from datetime import datetime
from flask import Flask, render_template
from flask_migrate import Migrate
from .models import User, db
from .main.errors import page_not_found

basedir = os.path.abspath(os.path.dirname(__file__))
migrate = Migrate()

def create_app():
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.getenv("FLASK_SECRET_KEY") or 'removed',
        SQLALCHEMY_DATABASE_URI='sqlite:///'+ os.path.join(basedir, 'cisstandaard.sqlite'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SQLALCHEMY_ECHO=True,
        SCAP_REPORT_DIR=os.getenv("SCAP_REPORT_DIR") or '/data/linux/py/baseline/reports',
        DEBUG=True
    )

    register_extensions(app)
    register_blueprints(app)
    register_context(app)
    register_shellcontext(app)
    register_errorhandlers(app)

    return app

def register_extensions(app):
    db.init_app(app)
    migrate.init_app(app, db)

def register_blueprints(app):
    from .auth.views import auth
    from .main.views import main
    from .account.views import account
    #app.register_blueprint(auth, url_prefix="/baseline")
    #app.register_blueprint(main, url_prefix="/baseline")
    #app.register_blueprint(account, url_prefix="/baseline/user")
    app.register_blueprint(auth)
    app.register_blueprint(main)
    app.register_blueprint(account, url_prefix="/user")

def register_context(app):
    def inject_now():
        return { 'now': datetime.utcnow() }

    app.context_processor(inject_now)

def register_shellcontext(app):
    def make_shell_context():
        return dict(db=db, User=User)

    app.shell_context_processor(make_shell_context)

def register_errorhandlers(app):
    app.register_error_handler(404, page_not_found)

