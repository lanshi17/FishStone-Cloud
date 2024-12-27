from flask_login import current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.fields.simple import BooleanField
from wtforms.validators import DataRequired, Email, Length, Optional, ValidationError, EqualTo
from app.models.models import User


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(message='请输入有效的电子邮件地址')])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('记住我')  # 记住我字段
    submit = SubmitField('登录')
    def validate(self,extra_validators=None):
        if not super(LoginForm, self).validate():
            return False
        if not self.password.data:  # 不需要检查验证码字段，因为这是密码登录
            self.password.errors.append('请输入密码')
            return False
        return True
        
    # def validate_username(self, field):
    #     print(f"验证用户名: {field.data}")
    #     if field.data != 'admin':
    #         raise ValidationError('用户名不存在.')
    
    # def validate_password(self, field):
    #     print(f"验证密码: {field.data}")
    #     if field.data != 'password':
    #         raise ValidationError('密码错误.')


class CodeLoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(message='请输入有效的邮箱地址')])
    verification_code = StringField('Verification Code', validators=[DataRequired(message='请输入验证码')])
    submit = SubmitField('Login')


def validate_email(form, field):
    user = User.query.filter_by(email=field.data).first()
    if user:
        raise ValidationError('该邮箱已被注册')


class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(message='请输入有效的邮箱地址'), validate_email])
    verification_code = StringField('Verification Code', validators=[Optional()])
    password = PasswordField('Password', validators=[Optional(), Length(min=8, message='密码至少8个字符')])
    submit = SubmitField('Register')
    send_code = SubmitField('Send Verification Code')
    confirm_password = PasswordField('Confirm Password', validators=[Optional(), EqualTo('password', message='密码不匹配，请重新输入')])


class ResetPasswordForm(FlaskForm):
    password = PasswordField('新密码', validators=[DataRequired(), Length(min=8, message="密码至少8个字符")])
    confirm_password = PasswordField('确认新密码', validators=[DataRequired(), EqualTo('password', message="密码不匹配")])
    submit = SubmitField('重置密码')

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(message='请输入有效的邮箱地址')])
    submit = SubmitField('Request Password Reset')

class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Old Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=8, message='密码至少8个字符')])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password', message='密码不匹配，请重新输入')])
    submit = SubmitField('Change Password')


class ChangeEmailForm(FlaskForm):
    email = StringField('New Email', validators=[DataRequired(), Email(message='请输入有效的邮箱地址'), validate_email])
    verification_code = StringField('Verification Code', validators=[Optional()])
    submit = SubmitField('Change Email')
    send_code = SubmitField('Send Verification Code')


class DeleteAccountForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    verification_code = StringField('Verification Code', validators=[DataRequired(), Length(min=6, max=6, message='验证码应为6位')])
    submit = SubmitField('Delete Account')
