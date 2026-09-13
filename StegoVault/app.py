import os
import re
import json
import time

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, send_from_directory, flash, abort,
)
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import stego_core as core

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USER_DB_PATH = os.path.join(BASE_DIR, 'users.json')

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'stegovault-secret-change-me')
    SESSION_TYPE = 'filesystem'
    SESSION_FILE_DIR = os.path.join(BASE_DIR, 'flask_session_data')
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024
    IMAGE_COVER_EXTS = {'png', 'bmp', 'jpg', 'jpeg', 'gif', 'webp', 'tiff'}
    AUDIO_COVER_EXTS = {'wav'}
    VIDEO_COVER_EXTS = {'mp4', 'mov', 'avi', 'mkv', 'webm', 'm4v', 'flv', 'wmv'}
    OUTPUT_EXTS = {'image': {'png', 'bmp'}, 'audio': {'wav'}, 'video': {'avi'}, 'file': set()}

app = Flask(__name__)
app.config.from_object(Config)
Session(app)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)


def load_users():
    if os.path.exists(USER_DB_PATH):
        try:
            with open(USER_DB_PATH, 'r', encoding='utf-8') as handle:
                data = json.load(handle)
                return data if isinstance(data, dict) else {}
        except Exception:
            pass
    return {}


def save_users(users):
    with open(USER_DB_PATH, 'w', encoding='utf-8') as handle:
        json.dump(users, handle, indent=2)


USERS = load_users()


def is_logged_in():
    return 'user_id' in session and 'username' in session


def username():
    return session.get('username', 'user')


def user_prefix():
    return username() + '_'


def allowed_ext(filename, extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in extensions


def sanitize_name(raw):
    cleaned = secure_filename(raw or '')
    return cleaned if cleaned else ('file_' + str(int(time.time())))


def output_name(suggested, ext_for, fallback):
    allowed = app.config['OUTPUT_EXTS'][ext_for]
    preferred = {'image': 'png', 'audio': 'wav', 'video': 'avi', 'file': 'bin'}.get(ext_for, 'bin')
    value = (suggested or '').strip() or fallback
    base, dot, given_ext = value.rpartition('.')
    if not dot:
        base, given_ext = value, ''
    base = secure_filename(base) or 'stego'
    if allowed and given_ext.lower() not in allowed:
        given_ext = preferred
    if not given_ext:
        given_ext = preferred
    return base + '.' + given_ext.lower()


def save_cover(exts):
    cover = request.files.get('cover_file')
    if not cover or not cover.filename:
        return None
    if exts is not None and not allowed_ext(cover.filename, exts):
        raise core.StegoError('Unsupported cover file type. Supported: ' +
                              ', '.join('.' + e for e in sorted(exts)))
    temp_path = os.path.join(app.config['UPLOAD_FOLDER'],
                             'temp_' + sanitize_name(cover.filename) + '_' + str(int(time.time())))
    cover.save(temp_path)
    return temp_path


def read_payload():
    password = request.form.get('password') or ''
    kind_of_payload = request.form.get('payload_type', 'text')
    if kind_of_payload == 'file':
        secret = request.files.get('secret_file')
        if not secret or not secret.filename:
            raise core.StegoError('No secret file was selected.')
        data = secret.read()
        name = sanitize_name(secret.filename)
        return core.KIND_FILE, name, data, password
    text = request.form.get('secret_text', '')
    if not text.strip():
        raise core.StegoError('No secret text was entered.')
    return core.KIND_TEXT, '', text.encode('utf-8'), password


def human_size(size_bytes):
    size = float(size_bytes)
    for unit in ('B', 'KB', 'MB', 'GB'):
        if size < 1024 or unit == 'GB':
            return '{:.2f} {}'.format(size, unit)
        size /= 1024
    return '{:.2f} GB'.format(size)


def vault_files():
    prefix = user_prefix()
    result = {'image': [], 'audio': [], 'video': [], 'file': []}
    if not os.path.isdir(app.config['UPLOAD_FOLDER']):
        return result
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        if not filename.startswith(prefix):
            continue
        if filename.startswith(('temp_', '_extract_')):
            continue
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if not os.path.isfile(path):
            continue
        ext = filename.rsplit('.', 1)[-1].lower()
        entry = {
            'name': filename,
            'size': human_size(os.path.getsize(path)),
            'date': time.strftime('%Y-%m-%d %H:%M', time.gmtime(os.path.getmtime(path))),
        }
        if ext in app.config['OUTPUT_EXTS']['image']:
            result['image'].append(entry)
        elif ext in app.config['OUTPUT_EXTS']['audio']:
            result['audio'].append(entry)
        elif ext in app.config['OUTPUT_EXTS']['video']:
            result['video'].append(entry)
        else:
            result['file'].append(entry)
    for category in result:
        result[category].sort(key=lambda item: item['name'].lower())
    return result


def store_extract_result(kind, file_name, data):
    if kind == core.KIND_TEXT:
        session['stego_result'] = {
            'kind': 'text',
            'text': data.decode('utf-8', errors='replace')[:200000],
        }
    else:
        safe_name = sanitize_name(file_name)
        stored = '_extract_' + user_prefix() + safe_name
        path = os.path.join(app.config['UPLOAD_FOLDER'], stored)
        with open(path, 'wb') as handle:
            handle.write(data)
        session['stego_result'] = {
            'kind': 'file',
            'filename': stored,
            'name': safe_name,
            'size': human_size(len(data)),
        }


def consume_extract_result():
    result = session.pop('stego_result', None)
    return result


def cleanup_extracts():
    prefix = '_extract_' + user_prefix()
    cutoff = time.time() - 6 * 3600
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        if not filename.startswith(prefix):
            continue
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        try:
            if os.path.getmtime(path) < cutoff:
                os.remove(path)
        except OSError:
            pass


def page_config(kind, title, blurb, cover_label, cover_accept, hint, cover_extra='', video=False):
    files = vault_files()
    out_exts = app.config['OUTPUT_EXTS'][kind]
    out_ext = '.' + sorted(out_exts)[0] if out_exts else ''
    return {
        'active_page': kind,
        'title': title,
        'blurb': blurb,
        'cover_label': cover_label,
        'cover_accept': cover_accept,
        'payload_hint': hint,
        'cover_extra': cover_extra,
        'is_video': video,
        'out_ext': out_ext,
        'files': files[kind],
        'result': consume_extract_result(),
        'dl': request.args.get('dl'),
        'kind': kind,
    }


# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if is_logged_in():
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''
        user = USERS.get(email)
        if user and verify_password(user['password'], password):
            session['user_id'] = email
            session['username'] = user.get('username') or email.split('@')[0]
            flash('Welcome back, {}!'.format(session['username']), 'success')
            return redirect(url_for('home'))
        flash('Invalid email or password.', 'error')
    return render_template('login.html')


def verify_password(stored, password):
    if stored.startswith(('pbkdf2:', 'scrypt:', 'sha256:')):
        return check_password_hash(stored, password)
    return stored == password


@app.route('/register', methods=['GET', 'POST'])
def register():
    if is_logged_in():
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        username_raw = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        confirm = request.form.get('confirm_password') or ''
        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
            flash('Please enter a valid email address.', 'error')
        elif not username_raw:
            flash('Please choose a username.', 'error')
        elif len(password) < 4:
            flash('Password must be at least 4 characters long.', 'error')
        elif password != confirm:
            flash('Passwords do not match.', 'error')
        elif USERS.get(email):
            flash('This email is already registered.', 'error')
        else:
            USERS[email] = {
                'password': generate_password_hash(password),
                'username': username_raw,
            }
            save_users(USERS)
            session['user_id'] = email
            session['username'] = username_raw
            flash('Account created. Welcome aboard!', 'success')
            return redirect(url_for('home'))
    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------

@app.route('/')
def index():
    if not is_logged_in():
        return redirect(url_for('login'))
    return redirect(url_for('home'))


@app.route('/home')
def home():
    if not is_logged_in():
        return redirect(url_for('login'))
    return render_template('home.html', active_page='home', files=vault_files())


@app.route('/about')
def about():
    if not is_logged_in():
        return redirect(url_for('login'))
    return render_template('about.html', active_page='about')


@app.route('/image')
def image_page():
    if not is_logged_in():
        return redirect(url_for('login'))
    return render_template('media.html', cfg=page_config(
        'image',
        'Image Steganography',
        'Hide text or any file inside an image using LSB substitution.',
        'Cover image',
        '.png,.bmp,.jpg,.jpeg,.gif,.webp,.tiff',
        'Type a message, or attach any file — a picture, song, video or document.',
        'JPG / GIF / WebP / TIFF covers are accepted and saved as lossless PNG / BMP.',
    ))


@app.route('/audio')
def audio_page():
    if not is_logged_in():
        return redirect(url_for('login'))
    return render_template('media.html', cfg=page_config(
        'audio',
        'Audio Steganography',
        'Hide text, images, audio or video inside any audio file. Output is a lossless WAV.',
        'Cover audio (WAV / MP3 / FLAC / OGG / M4A)',
        '.wav,.mp3,.flac,.ogg,.oga,.opus,.m4a,.aac,.aiff,.aif,.wma,.amr',
        'Type a message, or attach any file — a picture, song, video or document.',
        'MP3 / FLAC / OGG / M4A covers are transcoded and saved as lossless WAV.',
    ))


@app.route('/video')
def video_page():
    if not is_logged_in():
        return redirect(url_for('login'))
    return render_template('media.html', cfg=page_config(
        'video',
        'Video Steganography',
        'Hide text, images, audio or video inside any video. Output is a lossless AVI.',
        'Cover video (optional)',
        '.mp4,.mov,.avi,.mkv,.webm,.m4v,.flv,.wmv,.3gp,.mpg,.mpeg,.ogv',
        'Type a message, or attach any file — a picture, song, video or document.',
        video=True,
    ))


@app.route('/file')
def file_page():
    if not is_logged_in():
        return redirect(url_for('login'))
    return render_template('media.html', cfg=page_config(
        'file',
        'Any-File Steganography',
        'Use <em>any</em> file as the cover — documents, archives, images, executables, anything.',
        'Cover file (any type)',
        '',
        'Type a message, or attach any file — a picture, song, video or document.',
        'The cover is copied byte-for-byte with your secret written into its least significant bits.',
    ))


# --------------------------------------------------------------------------
# Embed / Extract handlers
# --------------------------------------------------------------------------

def handle_embed(cover_exts, kind, core_embed):
    temp_path = None
    try:
        kind_of_payload, file_name, data, password = read_payload()
        temp_path = save_cover(cover_exts)
        generate = request.form.get('generate') == '1' if kind == 'video' else False
        if not temp_path:
            if kind == 'file':
                raise core.StegoError('Upload a cover file to hide your secret inside.')
            if kind == 'video' and not generate:
                raise core.StegoError('Upload a cover video or tick "Automatic video".')
        fallback = 'stego'
        if kind == 'file':
            cover_fh = request.files.get('cover_file')
            if cover_fh and cover_fh.filename:
                cover_base = secure_filename(os.path.splitext(cover_fh.filename)[0]) or 'cover'
                cover_ext = os.path.splitext(cover_fh.filename)[1].lower().lstrip('.') or 'bin'
                fallback = cover_base + '_hidden.' + cover_ext
        final_name = output_name(request.form.get('output_filename'), kind, fallback)
        final_name = user_prefix() + final_name
        out_path = os.path.join(app.config['UPLOAD_FOLDER'], final_name)
        if kind == 'video':
            core_embed(temp_path, kind_of_payload, file_name, data, password, out_path, generate=generate)
        else:
            core_embed(temp_path, kind_of_payload, file_name, data, password, out_path)
        flash('Payload hidden successfully in {}'.format(final_name), 'success')
        return redirect(url_for(kind + '_page', dl=final_name))
    except core.StegoError as exc:
        flash(str(exc), 'error')
        return redirect(url_for(kind + '_page'))
    except Exception as exc:
        flash('An error occurred during embedding: {}'.format(exc), 'error')
        return redirect(url_for(kind + '_page'))
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


def handle_extract(kind, core_extract):
    temp_path = None
    try:
        embedded = request.files.get('embedded_file')
        if not embedded or not embedded.filename:
            flash('No file was selected for extraction.', 'error')
            return redirect(url_for(kind + '_page'))
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'],
                                 'temp_' + sanitize_name(embedded.filename) + '_' + str(int(time.time())))
        embedded.save(temp_path)
        password = request.form.get('password') or ''
        payload_kind, file_name, data = core_extract(temp_path, password)
        store_extract_result(payload_kind, file_name, data)
        flash('Payload extracted successfully!', 'success')
    except core.StegoError as exc:
        flash(str(exc), 'error')
    except Exception as exc:
        flash('An error occurred during extraction: {}'.format(exc), 'error')
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
    cleanup_extracts()
    return redirect(url_for(kind + '_page'))


@app.route('/image/embed', methods=['POST'])
def image_embed():
    if not is_logged_in():
        return redirect(url_for('login'))
    return handle_embed(app.config['IMAGE_COVER_EXTS'], 'image', core.embed_image)


@app.route('/image/extract', methods=['POST'])
def image_extract():
    if not is_logged_in():
        return redirect(url_for('login'))
    return handle_extract('image', core.extract_image)


@app.route('/audio/embed', methods=['POST'])
def audio_embed():
    if not is_logged_in():
        return redirect(url_for('login'))
    return handle_embed(None, 'audio', core.embed_audio)


@app.route('/audio/extract', methods=['POST'])
def audio_extract():
    if not is_logged_in():
        return redirect(url_for('login'))
    return handle_extract('audio', core.extract_audio)


@app.route('/video/embed', methods=['POST'])
def video_embed():
    if not is_logged_in():
        return redirect(url_for('login'))
    return handle_embed(None, 'video', core.embed_video)


@app.route('/video/extract', methods=['POST'])
def video_extract():
    if not is_logged_in():
        return redirect(url_for('login'))
    return handle_extract('video', core.extract_video)


@app.route('/file/embed', methods=['POST'])
def file_embed():
    if not is_logged_in():
        return redirect(url_for('login'))
    return handle_embed(None, 'file', core.embed_file)


@app.route('/file/extract', methods=['POST'])
def file_extract():
    if not is_logged_in():
        return redirect(url_for('login'))
    return handle_extract('file', core.extract_file)


# --------------------------------------------------------------------------
# Downloads
# --------------------------------------------------------------------------

@app.route('/download/<path:filename>')
def download(filename):
    if not is_logged_in():
        return redirect(url_for('login'))
    allowed_prefixes = (user_prefix(), '_extract_' + user_prefix())
    if not filename.startswith(allowed_prefixes):
        flash('Access denied to that file.', 'error')
        return redirect(url_for('home'))
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


@app.route('/delete/<path:filename>', methods=['POST'])
def delete_file(filename):
    if not is_logged_in():
        return redirect(url_for('login'))
    allowed_prefixes = (user_prefix(), '_extract_' + user_prefix())
    if not filename.startswith(allowed_prefixes) or filename.startswith('temp_'):
        flash('Access denied to that file.', 'error')
        return redirect(url_for('home'))
    safe = secure_filename(filename)
    if safe != filename:
        flash('Invalid filename.', 'error')
        return redirect(url_for('home'))
    path = os.path.join(app.config['UPLOAD_FOLDER'], safe)
    try:
        if not os.path.exists(path) or not os.path.isfile(path):
            flash('That file no longer exists.', 'error')
        else:
            os.remove(path)
            flash('Deleted {}'.format(safe), 'success')
    except OSError as exc:
        flash('Could not delete the file: {}'.format(exc), 'error')
    return redirect(request.referrer or url_for('home'))


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True, use_reloader=False)