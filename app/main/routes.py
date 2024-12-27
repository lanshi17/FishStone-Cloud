import logging
import os
import secrets
import re
from collections import Counter
from urllib.parse import unquote

import jieba
from pypinyin import lazy_pinyin
from os.path import join

from flask import (
    Blueprint, current_app, render_template, redirect, url_for, flash,
    jsonify, send_file, request
)
from flask_login import login_required, current_user
from sqlalchemy import func
from werkzeug.utils import secure_filename

from ..extensions import db
from app.main import main_bp
from app.models.file import File
from app.main.forms import UploadForm, ShareFileForm, SaveSharedFileForm
from ..utils.utils import format_file_size


# Helper function: Check if the file extension is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']


def delete_file(file_id):
    file_record = File.query.filter_by(id=file_id, user_id=current_user.id).first()
    if not file_record:
        return False, "文件不存在或无权删除该文件"
    file_path = file_record.get_full_path()

    if os.path.exists(file_path):
        try:
            os.remove(file_path)
            db.session.delete(file_record)
            db.session.commit()
            return True, "文件删除成功"
        except Exception as e:
            db.session.rollback()
            return False, f"文件删除失败: {str(e)}"
    else:
        return False, "文件不存在"


def custom_secure_filename(filename):
    """
    Custom version of secure_filename to keep Chinese characters and file extensions.
    """
    filename = filename.strip().replace(' ', '_')  # Replace spaces with underscores
    name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')

    # Keep Chinese characters and alphanumeric characters, and replace others with underscores
    name = re.sub(r'[^\w\u4e00-\u9fff]', '_', name)

    if ext:
        return f"{name}.{ext}"
    return name


# Home route
@main_bp.route('/')
def index():
    return render_template('index.html')


@main_bp.context_processor
def utility_processor():
    return dict(format_file_size=format_file_size)


@main_bp.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    form = UploadForm()
    if request.method == 'POST':
        try:
            if 'files' not in request.files:
                return jsonify(success=False, message="没有文件上传"), 400

            files = request.files.getlist('files')
            upload_results = []

            for file in files:
                if file and allowed_file(file.filename):
                    # 使用 custom_secure_filename 保留中文文件名
                    filename = custom_secure_filename(file.filename)
                    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)

                    # 确保文件名没有被错误过滤
                    if File.query.filter_by(filename=filename, user_id=current_user.id).first():
                        upload_results.append({'file': filename, 'success': False, 'message': '此文件已存在！'})
                        continue

                    file.save(file_path)
                    new_file = File(filename=filename, user_id=current_user.id, path=file_path)
                    db.session.add(new_file)
                    db.session.commit()

                    upload_results.append({'file': filename, 'success': True, 'message': '文件上传成功！'})
                else:
                    upload_results.append(
                        {'file': file.filename, 'success': False, 'message': '无效文件格式，请检查格式！'})

            return jsonify(success=True, upload_results=upload_results), 200

        except Exception as e:
            db.session.rollback()
            return jsonify(success=False, message=f"服务器错误: {str(e)}"), 500

    return render_template('upload.html', form=form)


# Share file route
@main_bp.route('/share/<int:file_id>', methods=['POST'])
@login_required
def share_file(file_id):
    file = File.query.filter_by(id=file_id, user_id=current_user.id).first()

    if not file:
        return jsonify({'success': False, 'message': '文件不存在！'}), 404

    # 如果没有分享 token，就生成一个
    if not file.share_token:
        file.share_token = secrets.token_urlsafe(16)
        db.session.commit()

    share_link = url_for('main.download_file', file_id=file.id, share_token=file.share_token, _external=True)

    return jsonify({'success': True, 'share_link': share_link})


@main_bp.route('/batch_share_file', methods=['GET', 'POST'])
@login_required
def batch_share_file():
    data = request.get_json()
    file_ids = data.get('file_ids')

    if not file_ids:
        return jsonify(success=False, message="没有文件被选中")

    try:
        for file_id in file_ids:
            file_record = File.query.filter_by(id=file_id, user_id=current_user.id).first()
            if file_record:
                if not file_record.share_token:
                    file_record.share_token = secrets.token_urlsafe(16)
                    db.session.commit()
        db.session.commit()
        return jsonify(success=True, message="文件分享成功")
    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, message=f"文件分享失败: {str(e)}")


# Save shared file route

def process_share_token(share_token):
    file = File.query.filter_by(share_token=share_token).first()
    if not file:
        return False

    file.share_token = None
    file.user_id = current_user.id
    db.session.commit()
    return True

@main_bp.route('/save_shared_file', methods=['GET', 'POST'])
@login_required
def save_shared_file():
    form = SaveSharedFileForm()

    if request.method == 'POST':  # Handle POST request
        if form.validate_on_submit():
            share_token = form.share_token.data
            if process_share_token(share_token):
                return jsonify({"success": True, "message": "文件保存成功！"})
            else:
                return jsonify({"success": False, "message": "无效的分享链接或代码"}), 400
        else:
            return jsonify({"success": False, "message": "表单验证失败", "errors": form.errors}), 400

    if request.method == 'GET':  # Handle GET request
        # Return the HTML form or other information for GET requests
        return render_template('save_shared_file.html', form=form)



# Download file route
@main_bp.route('/download/<int:file_id>', methods=['GET'])
@login_required
def download_file(file_id):
    file = File.query.filter_by(id=file_id, user_id=current_user.id).first()
    if not file:
        return jsonify({'success': False, 'message': '文件不存在'}), 404

    file.download_count += 1
    db.session.commit()
    return send_file(file.path, as_attachment=True, download_name=file.filename)


@main_bp.route('/files', defaults={'page': 1}, methods=['GET', 'POST'])
@main_bp.route('/files/page/<int:page>', methods=['GET'])
@login_required
def file_list(page):
    per_page = 10  # Display 10 files per page

    # Handle POST request (for deletion)
    if request.method == 'POST':
        file_id = request.form.get('file_id')
        success, message = delete_file(file_id)
        if success:
            flash(message, 'success')
        else:
            flash(message, 'danger')
        return redirect(url_for('main.file_list', page=page))

    # Handle GET request (for listing files)
    #pagination = File.query.filter_by(user_id=current_user.id).paginate(page, per_page, error_out=False)
    pagination = File.query.filter_by(user_id=current_user.id).paginate(page=page, per_page=per_page, error_out=False)

    return render_template('file_list.html', files=pagination.items, pagination=pagination)


# Batch delete route
@main_bp.route('/batch_delete', methods=['POST'])
@login_required
def batch_delete_files():
    data = request.get_json()
    file_ids = data.get('file_ids')

    if not file_ids:
        return jsonify(success=False, message="没有文件被选中")

    try:
        for file_id in file_ids:
            file_record = File.query.filter_by(id=file_id, user_id=current_user.id).first()
            if file_record:
                file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file_record.filename)
                if os.path.exists(file_path):
                    os.remove(file_path)
                db.session.delete(file_record)
        db.session.commit()
        flash("文件删除成功！", "success")
        return jsonify(success=True, message="文件删除成功")
    except Exception as e:
        db.session.rollback()
        flash("删除文件失败！", "danger")
        return jsonify(success=False, message=f"删除文件失败: {str(e)}")


def delete_file_from_filesystem(file_record):
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file_record.filename)
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
        except Exception as e:
            return False, f'文件删除失败: {str(e)}'
    return True, '文件删除成功！'


# Delete file route
@main_bp.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    current_app.logger.info(f"正在删除文件 ID: {file_id}")

    # 查询数据库中的文件
    file_record = File.query.filter_by(id=file_id, user_id=current_user.id).first()

    if not file_record:
        return jsonify({'success': False, 'message': '文件不存在或无权删除该文件'}), 404

    file_path = file_record.get_full_path()

    # 检查文件是否存在于文件系统中并尝试删除
    if os.path.exists(file_path):
        try:
            os.remove(file_path)  # 删除文件
            db.session.delete(file_record)  # 删除数据库记录
            db.session.commit()
            return jsonify({'success': True, 'message': '文件删除成功'}), 200
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f'文件删除失败: {str(e)}')
            return jsonify({'success': False, 'message': f'文件删除失败: {str(e)}'}), 500
    else:
        return jsonify({'success': False, 'message': '文件不存在'}), 404


# File statistics route
@main_bp.route('/stats')
@login_required
def view_stats():
    stats = db.session.query(
        func.count(File.id).label('total_files'),
        func.sum(File.download_count).label('total_downloads'),
        func.max(File.size).label('largest_file_size')
    ).first()

    largest_file = File.query.order_by(File.size.desc()).first()
    largest_file_name = largest_file.filename if largest_file else 'N/A'
    largest_file_size = largest_file.size if largest_file else 0

    return render_template('stats.html', stats={
        'total_files': stats.total_files or 0,
        'total_downloads': stats.total_downloads or 0,
        'largest_file': largest_file_name,
        'largest_file_size': largest_file_size
    })


# Word cloud and file upload stats
def process_file_names(files):
    all_words = []
    for file in files:
        file_name = file.filename.rsplit('.', 1)[0]

        words = [word for word in jieba.cut(file_name) if word.isalpha()]

        all_words.extend(words)
    all_words = [word for word in all_words if len(word) > 1]
    return all_words


@main_bp.route('/upload_stats')
@login_required
def upload_stats():
    files = File.query.filter_by(user_id=current_user.id).all()
    total_files = File.query.filter_by(user_id=current_user.id).count()
    total_downloads = db.session.query(db.func.sum(File.download_count)).filter_by(
        user_id=current_user.id).scalar() or 0
    most_downloaded_file = File.query.filter_by(user_id=current_user.id).order_by(File.download_count.desc()).first()
    most_downloaded = {
        'name': most_downloaded_file.filename if most_downloaded_file else 'N/A',
        'downloads': most_downloaded_file.download_count if most_downloaded_file else 0
    }
    largest_file = File.query.filter_by(user_id=current_user.id).order_by(File.size.desc()).first()
    largest_file_data = {
        'name': largest_file.filename if largest_file else 'N/A',
        'size': largest_file.size if largest_file else 0
    }

    all_words = process_file_names(files)

    word_freq = Counter(all_words)

    wordcloud_data = [{"name": word, "value": freq} for word, freq in word_freq.items()]

    monthly_uploads = {month: 0 for month in
                       ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']}

    for file in files:
        upload_month = file.created_at.strftime('%b')
        if upload_month in monthly_uploads:
            monthly_uploads[upload_month] += 1
    return jsonify({
        'total_files': total_files,
        'total_downloads': total_downloads,
        'most_downloaded': most_downloaded,
        'largest_file': largest_file_data,
        'monthly_uploads': monthly_uploads,
        'wordcloud_data': wordcloud_data
    })
