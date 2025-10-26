# backend/app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
import os
import sqlite3
import pickle
from werkzeug.utils import secure_filename
from datetime import datetime
import math
from collections import Counter
import zipfile
import string

# PDF text extraction + page count
from pdfminer.high_level import extract_text as pdf_extract_text
import pikepdf

# -------------------- Config --------------------
BASE_DIR = os.path.dirname(__file__)
UPLOAD_FOLDER = os.path.join(BASE_DIR, '..', 'uploads')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'mp4', 'mp3', 'docx'}

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, '..', 'frontend', 'templates'),
    static_folder=os.path.join(BASE_DIR, '..', 'frontend', 'static')
)
app.secret_key = "supersecretkey"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 256 * 1024 * 1024  # 256 MB
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# -------------------- Load model, scaler, feature names --------------------
MODEL_DIR = os.path.join(BASE_DIR, "model")
MODEL_FILE = os.path.join(MODEL_DIR, "random_forest_model.pkl")
SCALER_FILE = os.path.join(MODEL_DIR, "scaler.pkl")
FEATURE_NAMES_FILE = os.path.join(MODEL_DIR, "feature_names.pkl")

malware_model = None
scaler = None
FEATURE_NAMES = None
MALWARE_PROB_THRESHOLD = 0.85  # conservative threshold

try:
    if os.path.exists(SCALER_FILE):
        with open(SCALER_FILE, "rb") as f:
            scaler = pickle.load(f)
    if os.path.exists(MODEL_FILE):
        with open(MODEL_FILE, "rb") as f:
            malware_model = pickle.load(f)
    if os.path.exists(FEATURE_NAMES_FILE):
        with open(FEATURE_NAMES_FILE, "rb") as f:
            FEATURE_NAMES = pickle.load(f)
    print("Loaded model/scaler/features. Model:", bool(malware_model), "Scaler:", bool(scaler))
except Exception as e:
    print("Failed to load model/scaler:", e)
    malware_model = None
    scaler = None
    FEATURE_NAMES = None

# -------------------- Database --------------------
DB_PATH = os.path.join(BASE_DIR, "database.db")

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        email TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        first_name TEXT,
                        last_name TEXT
                    )''')
        c.execute('''CREATE TABLE IF NOT EXISTS messages (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        sender_id INTEGER,
                        receiver_id INTEGER,
                        subject TEXT,
                        body TEXT,
                        file TEXT,
                        timestamp TEXT,
                        FOREIGN KEY(sender_id) REFERENCES users(id),
                        FOREIGN KEY(receiver_id) REFERENCES users(id)
                    )''')
        conn.commit()

init_db()

# -------------------- Feature extraction --------------------
def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    probs = [count / len(data) for count in counts.values()]
    return -sum(p * math.log2(p) for p in probs)

def printable_ratio_raw(data: bytes) -> float:
    if not data:
        return 0.0
    printable = set(bytes(string.printable, 'ascii'))
    count = sum(1 for b in data if b in printable)
    return count / len(data) 

def extract_pdf_text_ratio(file_path: str) -> float:
    try:
        text = pdf_extract_text(file_path)
        if not text:
            return 0.0
        text_bytes = text.encode('utf-8', errors='ignore')
        total = os.path.getsize(file_path)
        if total <= 0:
            return 0.0
        return len(text_bytes) / float(total)
    except Exception:
        return 0.0

def get_pdf_page_count(file_path: str) -> int:
    try:
        with pikepdf.Pdf.open(file_path) as pdf:
            pages = pdf.root.get('/Pages')
            if pages and '/Count' in pages:
                return int(pages['/Count'])
            # fallback
            return len(pdf.pages)
    except Exception:
        try:
            with pikepdf.Pdf.open(file_path) as pdf:
                return len(pdf.pages)
        except Exception:
            return 0

def extract_raw_features(file_path):
    try:
        size_bytes = os.path.getsize(file_path)
        size_kb = size_bytes / 1024.0
    except:
        size_kb = 0.0
        size_bytes = 0

    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except:
        data = b""

    entropy = calculate_entropy(data)
    raw_printable = printable_ratio_raw(data)

    ext = os.path.splitext(file_path)[1].lower()
    ext_map = {'.exe': 1, '.pdf': 2, '.docx': 3, '.jpg': 4, '.png': 5, '.mp4': 6, '.mp3': 7, '.txt': 8}
    ext_code = ext_map.get(ext, 0)

    js_flag = openaction_flag = embed_flag = 0
    js_count = 0
    pdf_text_ratio = 0.0
    page_count = 0
    if ext == '.pdf':
        pdf_text_ratio = extract_pdf_text_ratio(file_path)
        page_count = get_pdf_page_count(file_path)
        # detect JavaScript using pikepdf (more accurate)
        try:
            with pikepdf.Pdf.open(file_path) as pdf:
                root = pdf.root
                if '/Names' in root:
                    names = root.get('/Names')
                    if names and ('/JavaScript' in str(names) or '/JavaScript' in repr(names)):
                        js_flag = 1
                        js_count += 1
                if '/OpenAction' in root:
                    oa = root.get('/OpenAction')
                    if oa and ('/JS' in str(oa) or '/JavaScript' in str(oa)):
                        js_flag = 1
                        js_count += 1
                for objnum, obj in pdf.objects.items():
                    try:
                        s = str(obj)
                        c = s.count('/JS') + s.count('/JavaScript')
                        if c:
                            js_count += c
                            js_flag = 1
                    except Exception:
                        continue
        except Exception:
            # fallback to byte-level heuristic
            try:
                s = data.decode(errors='ignore')
                js_flag = 1 if "/JS" in s or "/JavaScript" in s else 0
                js_count = s.count("/JS") + s.count("/JavaScript")
            except:
                js_flag = 0
                js_count = 0

    macro_flag = 0
    if ext == '.docx':
        try:
            with zipfile.ZipFile(file_path) as z:
                macro_flag = 1 if any("vbaProject.bin" in name for name in z.namelist()) else 0
        except:
            macro_flag = 0

    img_flag = 0
    try:
        if ext in ['.jpg', '.jpeg', '.png']:
            from PIL import Image
            img = Image.open(file_path)
            w,h = img.size
            img_flag = 1 if (w * h > 3000 * 3000) else 0
    except:
        img_flag = 0

    return {
        "size_kb": float(size_kb),
        "size_bytes": int(size_bytes),
        "entropy": float(entropy),
        "ext": int(ext_code),
        "js_flag": int(js_flag),
        "openaction_flag": int(openaction_flag),
        "embed_flag": int(embed_flag),
        "macro_flag": int(macro_flag),
        "img_flag": int(img_flag),
        "printable_ratio_raw": float(raw_printable),
        "pdf_text_ratio": float(pdf_text_ratio),
        "js_count": int(js_count),
        "page_count": int(page_count)
    }

def build_model_features(raw_feats):
    size_kb = raw_feats.get("size_kb", 0.0)
    log_size = math.log1p(size_kb)
    entropy = raw_feats.get("entropy", 0.0)
    entropy_per_kb = entropy / (log_size + 1e-6)
    ext = raw_feats.get("ext", 0)
    return [
        float(size_kb),
        float(log_size),
        float(entropy),
        float(entropy_per_kb),
        int(ext),
        int(raw_feats.get("js_flag", 0)),
        int(raw_feats.get("openaction_flag", 0)),
        int(raw_feats.get("embed_flag", 0)),
        int(raw_feats.get("macro_flag", 0)),
        int(raw_feats.get("img_flag", 0))
    ]

# -------------------- Helpers --------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_username(uid):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT email FROM users WHERE id=?", (uid,))
        row = c.fetchone()
        return row[0] if row else "Unknown"

def get_fullname(uid):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT first_name, last_name FROM users WHERE id=?", (uid,))
        row = c.fetchone()
        if row:
            fn = (row[0] or "").strip()
            ln = (row[1] or "").strip()
            full = (fn + " " + ln).strip()
            return full if full else get_username(uid)
        return get_username(uid)

# -------------------- Routes --------------------
@app.route('/')
def home():
    if 'user' in session:
        return redirect(url_for('profile'))
    return render_template('home.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            try:
                c.execute("INSERT INTO users (email, password, first_name, last_name) VALUES (?, ?, ?, ?)",
                          (email, password, first_name, last_name))
                conn.commit()
                flash("Registration successful!", "success")
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash("User already exists", "error")
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("SELECT id, email, password, first_name, last_name FROM users WHERE email=? AND password=?", (email, password))
            user = c.fetchone()
            if user:
                session['user'] = user[1]
                session['user_id'] = user[0]
                fn = (user[3] or "").strip()
                ln = (user[4] or "").strip()
                session['full_name'] = (fn + " " + ln).strip() if (fn+ln).strip() else user[1]
                flash("Login successful!", "success")
                return redirect(url_for('profile'))
            else:
                flash("Invalid credentials", "error")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('user_id', None)
    session.pop('full_name', None)
    return redirect(url_for('login'))

@app.route('/profile')
def profile():
    if 'user' not in session:
        return redirect(url_for('login'))
    full = session.get('full_name') or get_fullname(session.get('user_id'))
    return render_template('profile.html', user=session['user'], full_name=full)

@app.route('/compose', methods=['GET','POST'])
def compose():
    if 'user' not in session:
        return redirect(url_for('login'))
    sender_id = session['user_id']
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT id, email FROM users WHERE id != ?", (sender_id,))
        users = c.fetchall()

    if request.method == 'POST':
        receiver_id = request.form['receiver_id']
        subject = request.form.get('subject')
        body = request.form.get('body')
        file = request.files.get('file')
        filename = None

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            saved_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(saved_path)

        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("INSERT INTO messages (sender_id, receiver_id, subject, body, file, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                      (sender_id, receiver_id, subject, body, filename, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()

        flash("Message sent!", "success")
        return redirect(url_for('inbox'))

    return render_template('compose.html', users=users)

@app.route('/inbox')
def inbox():
    if 'user' not in session:
        return redirect(url_for('login'))
    uid = session['user_id']
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT id, sender_id, subject, timestamp, file FROM messages WHERE receiver_id=? ORDER BY id DESC", (uid,))
        rows = c.fetchall()
    messages = []
    for r in rows:
        messages.append({
            "id": r[0],
            "sender": get_username(r[1]),
            "subject": r[2],
            "timestamp": r[3],
            "file": r[4]
        })
    return render_template('inbox.html', messages=messages)

@app.route('/view_message/<int:mid>')
def view_message(mid):
    if 'user' not in session:
        return redirect(url_for('login'))
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT id, sender_id, receiver_id, subject, body, file, timestamp FROM messages WHERE id=?", (mid,))
        row = c.fetchone()
    if not row:
        flash("Message not found", "error")
        return redirect(url_for('inbox'))

    message = {
        "id": row[0],
        "sender": get_username(row[1]),
        "receiver": row[2],
        "subject": row[3],
        "body": row[4],
        "file": row[5],
        "timestamp": row[6]
    }

    threat = 0

    if message['file'] and malware_model and scaler:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], message['file'])
        if os.path.exists(file_path):
            raw = extract_raw_features(file_path)
            features = build_model_features(raw)
            try:
                import numpy as np
                X = np.array([features], dtype=float)
                Xs = scaler.transform(X)
                if hasattr(malware_model, "predict_proba"):
                    prob = malware_model.predict_proba(Xs)[0][1]
                else:
                    prob = float(malware_model.predict(Xs)[0])

                # effective printable ratio
                printable_raw = raw.get("printable_ratio_raw", 0.0)
                pdf_text_ratio = raw.get("pdf_text_ratio", 0.0)
                printable_effective = max(printable_raw, pdf_text_ratio)

                # safety override rules (updated to allow small & large benign files)
                safety_override = False
                js_flag = raw.get("js_flag",0)
                macro_flag = raw.get("macro_flag",0)
                embed_flag = raw.get("embed_flag",0)
                page_count = raw.get("page_count", 0)
                entropy_per_kb = features[3]

                # 1) If PDF contains lots of extracted text -> safe
                if pdf_text_ratio >= 0.30 and js_flag == 0 and macro_flag == 0 and embed_flag == 0:
                    safety_override = True

                # 2) Very large but text-dominant files -> safe 
                if raw.get("size_kb",0) > 2048 and printable_effective >= 0.25 and js_flag == 0 and macro_flag == 0 and embed_flag == 0:
                    safety_override = True

                # 3) Multi-page scanned documents (likely lecture notes) -> safe
                if page_count >= 10 and js_flag == 0 and macro_flag == 0 and embed_flag == 0:
                    safety_override = True
                if page_count >= 5 and printable_effective >= 0.05 and js_flag == 0 and macro_flag == 0 and embed_flag == 0:
                    safety_override = True

                # 4) Small files that are text-like (small reports, text files) -> safe
                # e.g., < 50 KB and mostly printable bytes
                if raw.get("size_kb",0) <= 50 and printable_effective >= 0.60 and js_flag == 0 and macro_flag == 0 and embed_flag == 0:
                    safety_override = True

                # 5) Printable bytes heuristic (handles pdfminer failures)
                if printable_effective >= 0.55 and js_flag == 0 and macro_flag == 0 and embed_flag == 0:
                    safety_override = True

                # Final decision: override safe if safety_override True, otherwise use model probability
                if safety_override:
                    threat = 0
                else:
                    threat = 1 if prob >= MALWARE_PROB_THRESHOLD else 0

            except Exception as e:
                print("Prediction error:", e)
                threat = 0

    return render_template('view_message.html', message=message, threat=threat)

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/force_open/<int:mid>')
def force_open(mid):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT file FROM messages WHERE id=?", (mid,))
        row = c.fetchone()
    if row and row[0]:
        return send_from_directory(app.config['UPLOAD_FOLDER'], row[0], as_attachment=True)
    else:
        flash("File not found", "error")
        return redirect(url_for('inbox'))

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
