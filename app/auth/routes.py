import logging
import random
import string
import time
import traceback
from datetime import timedelta, datetime
from email.utils import formataddr
from random import randint

from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token, verify_jwt_in_request, decode_token
from flask_jwt_extended.exceptions import NoAuthorizationError
from flask_mail import Message
from jwt import ExpiredSignatureError, InvalidTokenError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql.functions import user
from werkzeug.security import check_password_hash, generate_password_hash
from . import auth_bp
from flask import render_template, redirect, url_for, flash, request, session, current_app, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from app.models.models import User
from ..extensions import db, mail, login_manager
from .forms import LoginForm, RegistrationForm, ResetPasswordForm, ChangePasswordForm, ChangeEmailForm, \
    DeleteAccountForm, CodeLoginForm, RequestResetForm
from functools import wraps


### 工具函数 ###
def manage_verification_code(email, operation="generate", input_code=None):
    """
    Handles verification code generation, storage, and validation.

    :param email: User's email to send the verification code.
    :param operation: Either 'generate' or 'validate'.
    :param input_code: Used in 'validate' mode to check the input against the stored code.
    :return: Boolean (for validation) or None (for generation).
    """
    if operation == "generate":
        verification_code = generate_verification_code()
        session['verification_code'] = verification_code
        session['last_code_sent'] = time.time()
        return send_verification_email(email, verification_code)

    elif operation == "validate":
        return verify_code(input_code)


def generate_verification_code(length=6):
    """Generates a random numeric verification code of a specified length."""
    return ''.join(random.choices(string.digits, k=length))


def generate_reset_token(user, expires_sec=3600):
    # 将 expires_sec 转换为 timedelta
    token = create_access_token(identity=user.id, expires_delta=timedelta(seconds=expires_sec))
    return token


def send_verification_email(email, code):
    """Sends an email with the verification code to the user's email address."""
    try:
        msg = Message('FishStone Cloud:您的验证码', recipients=[email])
        msg.body = f'您的验证码是 {code}'
        mail.send(msg)
        return True
    except Exception as e:
        current_app.logger.error(f'发送邮件时出错: {e}')
        return False


def verify_code(input_code):
    stored_code = session.get('verification_code')
    print(f"Stored Code: {stored_code}, Input Code: {input_code}")
    if stored_code and stored_code == input_code:
        print("验证码验证成功")
        return True
    print("验证码验证失败")
    return False


def is_cooldown_active():
    """Checks if the cooldown period for sending a new verification code is still active."""
    last_sent = session.get('last_code_sent', 0)
    current_time = time.time()
    cooldown_time = 60  # 冷却时间
    if current_time - last_sent < cooldown_time:
        return True, cooldown_time - int(current_time - last_sent)
    return False, None


def handle_db_operation(operation):
    """Handle database operation with error handling."""
    try:
        operation()
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Database operation error: {e}")
        return False
    return True


def handle_user_login(user, form, use_code=False):
    """
    处理用户登录的逻辑。可以处理验证码登录或密码登录。
    :param user: 登录的用户对象
    :param form: 提交的表单
    :param use_code: 是否使用验证码登录，默认使用密码登录
    """
    if use_code:
        # 验证码登录
        user.verification_code = None  # 登录成功后，清除验证码
        db.session.commit()
        flash('验证码登录成功！', 'success')
    else:
        # 密码登录
        flash('密码登录成功！', 'success')

    login_user(user)
    return redirect(url_for('main.index'))


def cooldown_required(func):
    """Decorator to enforce cooldown period for sending verification code."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        is_cooldown, time_left = is_cooldown_active()
        if is_cooldown:
            return jsonify({'success': False, 'message': f'请等待 {time_left} 秒后再请求验证码。'}), 429
        return func(*args, **kwargs)

    return wrapper


### 路由 ###

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        email = session.get('email')  # 从会话中获取邮箱
        password = form.password.data
        verification_code = form.verification_code.data

        # 检查验证码是否有效
        stored_code = session.get('verification_code')
        verification_sent_at = session.get('verification_sent_at')
        if not stored_code or not verification_sent_at:
            flash('验证码不存在或已过期，请重新发送验证码。', 'danger')
            return redirect(url_for('auth.register'))

        # 检查验证码是否正确且不过期（假设10分钟过期）
        expiration_time = 600  # 10分钟
        if verification_code == stored_code and (datetime.utcnow() - datetime.strptime(verification_sent_at,
                                                                                       '%Y-%m-%d %H:%M:%S')).total_seconds() < expiration_time:
            try:
                # 插入新用户数据
                user = User(
                    email=email,
                    password_hash=generate_password_hash(password),  # 设置密码
                    verification_code=None,  # 清空验证码
                    verification_sent_at=None  # 清空验证码发送时间
                )
                db.session.add(user)
                db.session.commit()  # 提交事务

                login_user(user)
                flash('注册成功，请登录。', 'success')
                return redirect(url_for('main.index'))
            except IntegrityError:
                db.session.rollback()
                flash('该邮箱已被注册，请使用其他邮箱。', 'danger')
            except Exception as e:
                db.session.rollback()
                traceback.print_exc()
                flash(f'注册失败，请稍后再试。 错误: {str(e)}', 'danger')
            return redirect(url_for('auth.register'))
        else:
            flash('验证码错误或已过期，请重新发送验证码。', 'danger')

    return render_template('register.html', form=form)


@auth_bp.route('/send_code', methods=['POST'])
@cooldown_required
def send_code():
    email = request.form.get('email')
    if not email:
        return jsonify({'success': False, 'message': '邮箱地址是必需的。'}), 400
        # 生成验证码并发送给用户
    verification_code = generate_verification_code()
    # 生成验证码并存储在会话中
    session['verification_code'] = verification_code
    session['email'] = email
    session['verification_sent_at'] = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')  # 保存发送时间

    # 发送验证码（假设 send_verification_email 是你用于发送验证码的函数）
    send_verification_email(email, verification_code)

    return jsonify({'success': True, 'message': '验证码已发送到您的邮箱。'})


@auth_bp.route('/send_login_code', methods=['POST'])
def send_login_code():
    email = request.form.get('email')
    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({'success': False, 'message': '该电子邮件地址未注册'})

    # 生成并发送验证码
    verification_code = generate_verification_code()
    user.verification_code = verification_code
    db.session.commit()

    # 发送邮件
    send_verification_email(user.email, verification_code)

    return jsonify({'success': True, 'message': '验证码已发送'})


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    code_login_form = CodeLoginForm()
    # 调试：打印表单对象
    #print("表单初始化完成:", login_form)
    # 密码登录逻辑
    if login_form.validate_on_submit():
        email = login_form.email.data
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(login_form.password.data):
            return handle_user_login(user, login_form, use_code=False)
        else:
            flash('用户不存在或密码错误', 'danger')
            return redirect(url_for('auth.login'))

    return render_template('login.html', login_form=login_form, code_login_form=code_login_form)


@auth_bp.route('/email_login', methods=['GET', 'POST'])
def email_login():
    form = CodeLoginForm()

    # 显示表单时使用GET方法
    if request.method == 'GET':
        return render_template('login.html', form=form)

    # 验证码登录逻辑 (POST请求)
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()

        if not user:
            flash('用户不存在', 'danger')
            return redirect(url_for('auth.email_login'))

        # 验证验证码
        if user.verification_code == form.verification_code.data:
            return handle_user_login(user, form, use_code=True)
        else:
            flash('验证码错误，请重试。', 'danger')
            return redirect(url_for('auth.email_login'))

    return render_template('login.html', form=form)


@auth_bp.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    return jsonify(logged_in_as=current_user_id), 200


### 密码重置相关逻辑 ###

def send_reset_email(user):
    """发送密码重置邮件"""
    token = generate_reset_token(user)
    reset_url = url_for('auth.reset_password', token=token, _external=True)
    sender_name = "FishStone Cloud"
    sender_email = current_app.config['MAIL_USERNAME']
    msg = Message('重置密码请求',
                  sender=formataddr((sender_name, sender_email)),
                  recipients=[user.email])
    msg.body = f'''要重置您的密码，请访问以下链接：
{reset_url}

如果您没有请求此操作，请忽略此邮件，无需采取进一步操作。
'''
    mail.send(msg)


@auth_bp.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_reset_email(user)
        flash('如果该邮箱存在，重置密码链接将发送到该邮箱中。', 'info')
        return redirect(url_for('auth.login'))  # 这里的逻辑是正确的，不需要 token 参数

    return render_template('reset_password_request.html', title='重置密码', form=form)


@auth_bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    try:
        decoded_token = decode_token(token)
        user_id = decoded_token['sub']
        user = User.query.get(user_id)
    except ExpiredSignatureError:
        flash('该重置密码链接已过期。', 'warning')
        return redirect(url_for('auth.reset_password_request'))
    except InvalidTokenError:
        flash('该重置密码链接无效。', 'warning')
        return redirect(url_for('auth.reset_password_request'))

    if not user:
        flash('无效的用户。', 'danger')
        return redirect(url_for('auth.reset_password_request'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        print("表单验证成功")
        hashed_password = generate_password_hash(form.password.data)
        user.password_hash = hashed_password
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"Error while updating password: {e}")
            flash('更新密码时发生错误，请稍后再试。', 'danger')

        flash('您的密码已更新！您现在可以登录了。', 'success')
        return redirect(url_for('auth.login'))
    else:
        print("表单验证失败: ", form.errors)

    return render_template('reset_password.html', form=form, token=token)


### 账户相关逻辑 ###

@auth_bp.route('/change_email', methods=['GET', 'POST'])
@login_required
def change_email():
    form = ChangeEmailForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            # 发送验证码逻辑
            if form.send_code.data:
                try:
                    manage_verification_code(form.email.data, operation="generate")
                    return jsonify({'success': True, 'message': '验证码已发送，请查收您的电子邮件。'})
                except Exception as e:
                    return jsonify({'success': False, 'message': '发送验证码失败，请稍后再试。'}), 500

            # 修改邮箱逻辑
            elif form.submit.data:
                if verify_code(form.verification_code.data):
                    try:
                        current_user.email = form.email.data
                        db.session.commit()
                        flash('您的邮箱已更新，请重新登录。', 'success')
                        return jsonify({'success': True, 'message': '您的邮箱已更新，请重新登录！'})
                    except Exception as e:
                        flash('更新邮箱失败，请稍后再试。', 'danger')
                        return jsonify({'success': False, 'message': '更新邮箱失败，请稍后再试。'}), 500
                else:
                    flash('验证码无效，请重新尝试。', 'danger')
                    return jsonify({'success': False, 'message': '验证码无效，请重新尝试。'}), 400

        # 如果表单验证失败，则返回更详细的错误信息
        return jsonify({
            'success': False,
            'message': '表单验证失败，请检查输入信息。',
            'errors': form.errors  # 将详细的错误信息返回前端
        }), 400
    else:
        return render_template('change_email.html', form=form)


@auth_bp.route('/send_delete_account_code', methods=['POST'])
@login_required
def send_delete_account_code():
    # 生成6位验证码
    verification_code = generate_verification_code()
    print(f"Generated Verification Code: {verification_code}")
    # 存储验证码和发送时间到当前用户对象
    current_user.set_verification_code(verification_code)

    # 提交数据库
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': '发送验证码时发生错误，请稍后再试。'})

    # 假设你有一个发送邮件的函数
    send_verification_email(current_user.email, verification_code)

    return jsonify({'success': True, 'message': '验证码已发送到您的电子邮箱。'})


def delete_user_files(user):
    for file in user.files:
        print(f"正在删除文件: {file.path}")
        try:
            if os.path.exists(file.path):
                os.remove(file.path)
            print(f"文件 {file.path} 删除成功。")
        except Exception as e:
            print(f"删除文件 {file.path} 时出错: {e}")
    print("所有文件已删除。")


@auth_bp.route('/delete_account', methods=['POST', 'GET'])
@login_required
def delete_account():
    form = DeleteAccountForm()
    if request.method == 'GET':
        return render_template('delete_account.html', form=form)
    if form.validate_on_submit():
        # 检查验证码是否正确
        input_code = form.verification_code.data
        if current_user.check_verification_code(input_code):
            try:
                # 删除用户文件
                delete_user_files(current_user)
                # 删除用户
                db.session.delete(current_user)
                db.session.commit()

                flash('您的账户和所有文件已成功删除。', 'success')

                # 注销用户
                logout_user()

                # 成功删除账户，返回 JSON
                return jsonify({'success': True, 'message': '账户删除成功'})

            except Exception as e:
                db.session.rollback()
                return jsonify({'success': False, 'message': '删除账户时发生错误，请稍后再试。'})
        else:
            return jsonify({'success': False, 'message': '验证码错误或已过期，请重新发送验证码。'})

    return jsonify({'success': False, 'message': '表单验证失败，请检查输入信息。'})


@auth_bp.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if check_password_hash(current_user.password_hash, form.old_password.data):
            current_user.set_password(form.new_password.data)
            success = handle_db_operation(lambda: None)
            if success:
                flash('密码已更改，请重新登录。', 'success')
                logout_user()
                return redirect(url_for('auth.login'))
        flash('旧密码错误。', 'danger')

    return render_template('change_password.html', form=form)


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('您已成功登出。', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/user_center', methods=['GET'])
@login_required
def user_center():
    return render_template('user_center.html')
