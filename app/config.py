import os
from datetime import timedelta
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(24).hex()
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', os.urandom(24).hex())
    JWT_ALGORITHM = 'HS256'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    # TDSQL-C for MySQL Database Configuration
    # TDSQL-C for MySQL Database Configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False # Avoids SQLAlchemy warning
    SQLALCHEMY_ECHO = False # Set to True to see all SQL queries
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
    # 允许上传的文件类型,包括常见的图片、文档、压缩文件等
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx', 'zip',
                          'rar', '7z', 'gz', 'tar', 'mp4', 'avi', 'mkv', 'flv', 'mov', 'wmv', 'mp3', 'wav', 'flac',
                          'wma',
                          'aac', 'ogg', 'csv', 'json', 'xml', 'html', 'css', 'js', 'py', 'c', 'cpp', 'java', 'md',
                          'yml',
                          'yaml', 'toml', 'ini', 'cfg', 'conf', 'log', 'sql', 'db', 'sqlite', 'psd', 'ai', 'svg', 'eps',
                          'ttf', 'otf', 'woff', 'woff2', 'eot', 'apk', 'exe', 'dmg', 'iso', 'img', 'bin', 'dll', 'deb',
                          'rpm', 'sh', 'bat', 'cmd', 'vbs', 'ps1', 'reg', 'jar'}
    MAX_CONTENT_LENGTH = 1024 * 1024 * 1024  # 1024 MB

    # Flask-Mail Configuration
    MAIL_SERVER = 'smtp.vip.163.com'
    MAIL_PORT = 465
    MAIL_USE_SSL = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = MAIL_USERNAME
    from flask import make_response


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'  # Use in-memory database for tests
    WTF_CSRF_ENABLED = False  # Typically disable CSRF protection for tests
