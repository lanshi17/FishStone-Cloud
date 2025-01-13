import os

from app import create_app

app = create_app()
upload_folder = app.config['UPLOAD_FOLDER']
if not os.path.exists(upload_folder):
    os.makedirs(upload_folder)

print("当前环境:", app.config.get('ENV'))

if __name__ == '__main__':
    app.run(debug=True)
