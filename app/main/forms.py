from flask import flash, url_for, redirect
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import SubmitField
from wtforms.fields.simple import StringField
from wtforms.validators import DataRequired


class UploadForm(FlaskForm):
    files = FileField('Upload Files', validators=[FileRequired()])
    submit = SubmitField('Upload')

class ShareFileForm(FlaskForm):
    filename = StringField('Filename', validators=[DataRequired()])
    submit = SubmitField('Generate Share Link')

class SaveSharedFileForm(FlaskForm):
    share_token = StringField('分享链接或代码', validators=[DataRequired()])