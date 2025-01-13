from flask import current_app
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask_wtf import CSRFProtect
from dotenv import load_dotenv

# 加载 .env 文件
load_dotenv()


# 初始化扩展
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
mail = Mail()
csrf = CSRFProtect()


def init_extensions(app):
    # 初始化所有扩展
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    mail.init_app(app)
    csrf.init_app(app)

    # 注册加载用户回调
    login_manager.user_loader(load_user)
    #
    # # 在应用中设置 CSP 头
    # @app.after_request
    # def set_csp_headers(response):
    #     response.headers['Content-Security-Policy'] = (
    #         "default-src 'self'; "
    #         "font-src 'self' https://fonts.gstatic.com; "  # 允许加载字体
    #         "script-src 'self' 'unsafe-inline'; "  # 允许执行内联脚本
    #         "style-src 'self' 'unsafe-inline'; "  # 允许内联样式
    #     )
    #     return response


def load_user(user_id):
    from app.models.models import User  # 防止循环导入
    return User.query.get(int(user_id))


def generate_token(email):
    serializer = Serializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-salt')


def confirm_token(token, expiration=600):
    serializer = Serializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=expiration)
    except:
        return False
    return email


def send_verification_email(email, code):
    msg = Message('Your Verification Code', recipients=[email])
    msg.body = f'Your verification code is: {code}'
    mail.send(msg)
