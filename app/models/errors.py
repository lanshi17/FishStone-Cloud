from flask import render_template

def init_app(app):
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        # Assuming 'db' is the SQLAlchemy instance imported
        from ..extensions import db
        db.session.rollback()
        return render_template('500.html'), 500
