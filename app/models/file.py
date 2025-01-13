import os
from datetime import datetime
from os.path import getsize
from flask import current_app
from ..extensions import db
from ..utils.utils import format_file_size


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256), nullable=False)
    size = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', back_populates='files', lazy=True)
    share_token = db.Column(db.String(32), unique=True, nullable=True)
    download_count = db.Column(db.Integer, default=0)
    path = db.Column(db.String(256), nullable=False)


    def __init__(self, filename, path, user_id, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.filename = filename
        self.path = path
        self.user_id = user_id
        self.ensure_directory_exists()  # Ensure directory exists
        self.size = self.calculate_size()

    def get_formatted_size(self):
        return format_file_size(self.size)

    def calculate_size(self):
        """Calculate the size of the file and store it in the `size` attribute."""
        file_path = self.get_full_path()
        return getsize(file_path) if os.path.exists(file_path) else 0

    def get_full_path(self):
        """Get the full absolute path of the file."""
        return os.path.abspath(os.path.join(current_app.config['UPLOAD_FOLDER'], self.path))

    def ensure_directory_exists(self):
        """Ensure the upload directory exists."""
        full_path = os.path.dirname(self.get_full_path())
        if not os.path.exists(full_path):
            os.makedirs(full_path)

    def delete_file(self):
        """Delete the file from the file system."""
        file_path = self.get_full_path()
        if os.path.exists(file_path):
            os.remove(file_path)

    def __repr__(self):
        return f"<File(filename='{self.filename}', size='{self.get_formatted_size()}', user_id={self.user_id}, created_at={self.created_at})>"

