import logging
from flask import has_request_context, request

from run import app


class RequestFormatter(logging.Formatter):
    def format(self, record):
        if has_request_context():
            record.url = request.url
            record.method = request.method
        else:
            record.url = None
            record.method = None
        return super().format(record)

# Configure your logging
handler = logging.StreamHandler()
handler.setFormatter(RequestFormatter(
    '[%(asctime)s] %(method)s %(url)s %(levelname)s: %(message)s'
))
app.logger.addHandler(handler)
app.logger.setLevel(logging.DEBUG)

import logging
from flask import has_request_context, request

logging.basicConfig(level=logging.DEBUG)

@app.before_request
def log_request_info():
    if has_request_context():
        app.logger.debug('Headers: %s', request.headers)
        app.logger.debug('Body: %s', request.get_data())

import logging
from logging.handlers import RotatingFileHandler
import os

if not app.debug:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/yourapp.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)

    app.logger.setLevel(logging.INFO)
    app.logger.info('YourApp startup')

