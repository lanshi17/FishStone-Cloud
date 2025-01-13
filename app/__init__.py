from flask import Flask
from app.config import Config
from .extensions import init_extensions,db
from .main import main_bp
from .auth import auth_bp
from .models.errors import init_app as init_error_handlers
from flask_jwt_extended import JWTManager


def create_app(config_class=Config):
    app = Flask(__name__, static_folder='static', template_folder='templates')
    app.config.from_object(config_class)
    JWTManager(app)
    

    init_extensions(app)  # Initialize extensions like db and login_manager
    init_error_handlers(app)  # Initialize error handlers

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)


    return app

# 暴露 db 对象，使得 `from app import db` 可用
__all__ = ['create_app', 'db']
