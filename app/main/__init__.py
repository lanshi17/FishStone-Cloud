from flask import Blueprint

main_bp = Blueprint('main', __name__)

from . import routes  # Ensure this import is at the end of the file
# Compare this snippet from app/auth/routes.py: