from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from ..extensions import db


class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # 添加验证码字段，存储6位验证码，增加发送时间，便于管理过期逻辑
    verification_code = db.Column(db.String(6))
    verification_sent_at = db.Column(db.DateTime)

    files = db.relationship('File', back_populates='user', lazy=True, cascade="all, delete-orphan")

    # 设置密码的函数
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # 检查密码的函数
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # 生成验证码
    def set_verification_code(self, code):
        self.verification_code = code
        self.verification_sent_at = datetime.utcnow()  # 记录发送时间

    # 检查验证码是否有效（默认600秒，即10分钟）
    def check_verification_code(self, code, expiration=600):
        if self.verification_code != code:
            return False
        if (datetime.utcnow() - self.verification_sent_at).total_seconds() > expiration:
            return False
        return True
