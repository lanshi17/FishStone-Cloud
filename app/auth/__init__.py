from flask import Blueprint

# 创建一个 'auth' 蓝图
auth_bp = Blueprint('auth', __name__, template_folder='templates')

# 从当前目录导入路由模块
from . import routes
