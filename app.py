from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os, json, re
import jwt
import datetime

app = Flask(__name__)
CORS(app, origins=["http://localhost:3000"])

# ── Secret key ────────────────────────────────────────────────────────────────
# In production, set this via environment variable:
#   export SECRET_KEY="something-very-random"
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-me-in-production')

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR     = os.path.abspath(os.path.dirname(__file__))
UPLOADS_ROOT = os.path.join(BASE_DIR, 'uploads')   # uploads/<code_slug>/...
CODES_FILE   = os.path.join(BASE_DIR, 'codes.json') # { slug: hashed_code }

os.makedirs(UPLOADS_ROOT, exist_ok=True)

# ── Code registry helpers ─────────────────────────────────────────────────────

def load_codes() -> dict:
    """Return { slug: hashed_code } from codes.json, or {} if missing."""
    if not os.path.exists(CODES_FILE):
        return {}
    with open(CODES_FILE, 'r') as f:
        return json.load(f)

def save_codes(codes: dict):
    with open(CODES_FILE, 'w') as f:
        json.dump(codes, f, indent=2)

def code_to_slug(code: str) -> str:
    """
    Turn any user code into a safe filesystem directory name.
    e.g. "My Secret Code!" -> "my-secret-code"
    """
    slug = code.lower().strip()
    slug = re.sub(r'[^a-z0-9]+', '-', slug)   # replace non-alphanumeric with dash
    slug = slug.strip('-')[:64]                 # max 64 chars
    return slug or 'default'

def user_folder(slug: str) -> str:
    """Absolute path to this user's private upload folder."""
    folder = os.path.join(UPLOADS_ROOT, slug)
    os.makedirs(folder, exist_ok=True)
    return folder

# ── JWT helpers ───────────────────────────────────────────────────────────────

def make_token(slug: str) -> str:
    return jwt.encode(
        {
            'sub': slug,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        },
        app.config['SECRET_KEY'],
        algorithm='HS256'
    )

def decode_token(token: str):
    payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    return payload.get('sub')   # returns slug or raises

def get_current_slug():
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return None
    try:
        return decode_token(auth.split(' ', 1)[1])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        slug = get_current_slug()
        if not slug:
            return jsonify({"success": False, "message": "Unauthorized. Please log in."}), 401
        return f(*args, slug=slug, **kwargs)
    return decorated

# ── Auth routes ───────────────────────────────────────────────────────────────

@app.route('/login', methods=['POST'])
def login():
    """
    Accepts { "code": "user's chosen code" }.

    Behaviour:
      • First time using a code  → registers it (hashed) and creates a private folder.
      • Subsequent uses           → verifies the code matches the stored hash.

    Every code is its own isolated account. No usernames, no email.
    """
    data = request.get_json(silent=True) or {}
    raw_code = data.get('code', '').strip()

    if not raw_code:
        return jsonify({"success": False, "message": "Code is required."}), 400

    if len(raw_code) < 4:
        return jsonify({"success": False, "message": "Code must be at least 4 characters."}), 400

    slug   = code_to_slug(raw_code)
    codes  = load_codes()

    if slug not in codes:
        # ── First use: register this code ──
        codes[slug] = generate_password_hash(raw_code)
        save_codes(codes)
        user_folder(slug)          # create the directory
        is_new = True
    else:
        # ── Returning user: verify ──
        if not check_password_hash(codes[slug], raw_code):
            return jsonify({"success": False, "message": "Incorrect code."}), 401
        is_new = False

    token = make_token(slug)
    return jsonify({
        "success":  True,
        "token":    token,
        "code_id":  slug,
        "is_new":   is_new,
        "message":  "Account created!" if is_new else "Welcome back!"
    })


@app.route('/logout', methods=['POST'])
def logout():
    # JWT is stateless — client discards the token.
    return jsonify({"success": True, "message": "Logged out."})


@app.route('/me', methods=['GET'])
@login_required
def me(slug):
    return jsonify({"success": True, "code_id": slug})

# ── File routes ───────────────────────────────────────────────────────────────
# All file operations are scoped to the authenticated user's folder.

@app.route('/upload', methods=['POST'])
@login_required
def upload_file(slug):
    if 'file' not in request.files:
        return jsonify({"success": False, "message": "No file part."}), 400

    file = request.files['file']
    if not file.filename:
        return jsonify({"success": False, "message": "No file selected."}), 400

    folder = user_folder(slug)
    dest   = os.path.join(folder, os.path.basename(file.filename))
    file.save(dest)
    return jsonify({"success": True, "message": "Uploaded.", "filename": os.path.basename(dest)})


@app.route('/uploads/<filename>')
@login_required
def serve_file(filename, slug):
    """Serve a file — only to the user who owns it."""
    folder = user_folder(slug)
    return send_from_directory(folder, filename)


@app.route('/files', methods=['GET'])
@login_required
def list_files(slug):
    folder = user_folder(slug)
    files  = [f for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f))]
    return jsonify({"files": files})


@app.route('/delete', methods=['POST'])
@login_required
def delete_file(slug):
    data     = request.get_json(silent=True) or {}
    filename = data.get('filename', '')

    if not filename:
        return jsonify({"success": False, "message": "Filename required."}), 400

    path = os.path.join(user_folder(slug), os.path.basename(filename))
    if not os.path.isfile(path):
        return jsonify({"success": False, "message": "File not found."}), 404

    try:
        os.remove(path)
        return jsonify({"success": True, "message": "Deleted."})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/save', methods=['POST'])
@login_required
def save_file(slug):
    data     = request.get_json(silent=True) or {}
    filename = data.get('filename', '')
    content  = data.get('content')

    if not filename or content is None:
        return jsonify({"success": False, "message": "Filename and content required."}), 400

    path = os.path.join(user_folder(slug), os.path.basename(filename))
    try:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        return jsonify({"success": True, "message": "Saved."})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/create-folder', methods=['POST'])
@login_required
def create_folder(slug):
    data        = request.get_json(silent=True) or {}
    folder_name = data.get('folderName', '').strip()

    if not folder_name:
        return jsonify({"success": False, "message": "Folder name required."}), 400

    safe_name   = os.path.basename(folder_name)
    folder_path = os.path.join(user_folder(slug), safe_name)

    if os.path.exists(folder_path):
        return jsonify({"success": False, "message": "Folder already exists."}), 400

    try:
        os.makedirs(folder_path)
        return jsonify({"success": True, "message": "Folder created."})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

# ── Static / index ────────────────────────────────────────────────────────────

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

if __name__ == '__main__':
    app.run(debug=True)
