import os
import sqlite3
import uuid
import json
import re
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory, flash, abort
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading"
)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(os.path.dirname(__file__), 'database'), exist_ok=True)

# ========== DATABASE HELPERS ==========
def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone TEXT,
        password_hash TEXT NOT NULL,
        profile_pic TEXT DEFAULT 'default.png',
        bio TEXT DEFAULT '',
        is_online INTEGER DEFAULT 0,
        is_admin INTEGER DEFAULT 0,
        is_blocked INTEGER DEFAULT 0,
        email_private INTEGER DEFAULT 1,
        last_seen TEXT DEFAULT CURRENT_TIMESTAMP,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS friend_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        status TEXT DEFAULT 'pending',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(sender_id, receiver_id)
    );

    CREATE TABLE IF NOT EXISTS friendships (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        friend_id INTEGER NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (friend_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(user_id, friend_id)
    );

    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        content TEXT,
        message_type TEXT DEFAULT 'text',
        file_url TEXT,
        reply_to INTEGER,
        is_edited INTEGER DEFAULT 0,
        is_deleted INTEGER DEFAULT 0,
        status TEXT DEFAULT 'sent',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        content TEXT NOT NULL,
        link TEXT,
        is_read INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS calls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        caller_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        call_type TEXT NOT NULL,
        status TEXT DEFAULT 'missed',
        duration INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (caller_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS blocked_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        blocked_id INTEGER NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (blocked_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(user_id, blocked_id)
    );

    CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        reporter_id INTEGER NOT NULL,
        reported_id INTEGER NOT NULL,
        reason TEXT NOT NULL,
        status TEXT DEFAULT 'open',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (reporter_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (reported_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages(sender_id, receiver_id);
    CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, is_read);
    CREATE INDEX IF NOT EXISTS idx_friendship_user ON friendships(user_id);
    ''')

    # Create default admin
    c.execute("SELECT * FROM users WHERE username=?", (app.config['ADMIN_USERNAME'],))
    if not c.fetchone():
        c.execute("""INSERT INTO users (full_name, username, email, password_hash, is_admin, bio)
                     VALUES (?, ?, ?, ?, 1, 'System Administrator')""",
                  ('Administrator', app.config['ADMIN_USERNAME'],
                   'admin@connectx.local',
                   generate_password_hash(app.config['ADMIN_PASSWORD'])))
    conn.commit()
    conn.close()

# ========== AUTH HELPERS ==========
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        conn = get_db()
        user = conn.execute("SELECT is_admin FROM users WHERE id=?", (session['user_id'],)).fetchone()
        conn.close()
        if not user or not user['is_admin']:
            abort(403)
        return f(*args, **kwargs)
    return decorated

def current_user():
    if 'user_id' not in session:
        return None
    conn = get_db()
    u = conn.execute("SELECT * FROM users WHERE id=?", (session['user_id'],)).fetchone()
    conn.close()
    return u

def are_friends(uid1, uid2):
    conn = get_db()
    r = conn.execute("""SELECT 1 FROM friendships WHERE user_id=? AND friend_id=?""",
                     (uid1, uid2)).fetchone()
    conn.close()
    return r is not None

def is_blocked(uid1, uid2):
    conn = get_db()
    r = conn.execute("""SELECT 1 FROM blocked_users
                        WHERE (user_id=? AND blocked_id=?) OR (user_id=? AND blocked_id=?)""",
                     (uid1, uid2, uid2, uid1)).fetchone()
    conn.close()
    return r is not None

# ========== ROUTES ==========
@app.route('/')
def index():
    return render_template('index.html', user=current_user())

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form
        full_name = data.get('full_name', '').strip()
        username = data.get('username', '').strip().lower()
        email = data.get('email', '').strip().lower()
        phone = data.get('phone', '').strip()
        password = data.get('password', '')
        confirm = data.get('confirm_password', '')

        errors = []
        if len(full_name) < 2: errors.append('Full name must be at least 2 characters.')
        if not re.match(r'^[a-z0-9_]{3,20}$', username):
            errors.append('Username must be 3-20 characters (letters, numbers, underscore).')
        if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
            errors.append('Invalid email address.')
        if len(password) < 8: errors.append('Password must be at least 8 characters.')
        if password != confirm: errors.append('Passwords do not match.')

        conn = get_db()
        if conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
            errors.append('Username already taken.')
        if conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone():
            errors.append('Email already registered.')

        profile_pic = 'default.png'
        file = request.files.get('profile_pic')
        if file and file.filename:
            ext = file.filename.rsplit('.', 1)[-1].lower()
            if ext in {'png', 'jpg', 'jpeg', 'gif', 'webp'}:
                fname = f"{uuid.uuid4().hex}.{ext}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], fname))
                profile_pic = fname

        if errors:
            conn.close()
            return render_template('register.html', errors=errors, data=data)

        try:
            conn.execute("""INSERT INTO users (full_name, username, email, phone, password_hash, profile_pic)
                            VALUES (?, ?, ?, ?, ?, ?)""",
                         (full_name, username, email, phone, generate_password_hash(password), profile_pic))
            conn.commit()
        except Exception as e:
            conn.close()
            return render_template('register.html', errors=[str(e)], data=data)
        conn.close()
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', errors=[], data={})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ident = request.form.get('identifier', '').strip().lower()
        password = request.form.get('password', '')
        remember = request.form.get('remember')

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=? OR email=?", (ident, ident)).fetchone()
        if user and user['is_blocked']:
            conn.close()
            return render_template('login.html', error='Account is blocked. Contact admin.')
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session.permanent = bool(remember)
            conn.execute("UPDATE users SET is_online=1, last_seen=CURRENT_TIMESTAMP WHERE id=?", (user['id'],))
            conn.commit()
            conn.close()
            if user['is_admin']:
                return redirect(url_for('admin_panel'))
            return redirect(url_for('dashboard'))
        conn.close()
        return render_template('login.html', error='Invalid username/email or password.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    uid = session.get('user_id')
    if uid:
        conn = get_db()
        conn.execute("UPDATE users SET is_online=0, last_seen=CURRENT_TIMESTAMP WHERE id=?", (uid,))
        conn.commit()
        conn.close()
        socketio.emit('user_offline', {'user_id': uid})
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    uid = session['user_id']
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

    total_friends = conn.execute("SELECT COUNT(*) as c FROM friendships WHERE user_id=?", (uid,)).fetchone()['c']
    pending_requests = conn.execute(
        "SELECT COUNT(*) as c FROM friend_requests WHERE receiver_id=? AND status='pending'", (uid,)).fetchone()['c']
    unread_msgs = conn.execute(
        "SELECT COUNT(*) as c FROM messages WHERE receiver_id=? AND status!='seen' AND is_deleted=0", (uid,)).fetchone()['c']
    unread_notifs = conn.execute(
        "SELECT COUNT(*) as c FROM notifications WHERE user_id=? AND is_read=0", (uid,)).fetchone()['c']

    friends = conn.execute("""SELECT u.* FROM users u
                             JOIN friendships f ON f.friend_id=u.id
                             WHERE f.user_id=? ORDER BY u.is_online DESC, u.full_name""", (uid,)).fetchall()

    recent = conn.execute("""SELECT u.id, u.full_name, u.username, u.profile_pic, u.is_online,
                             (SELECT content FROM messages WHERE ((sender_id=u.id AND receiver_id=?) OR (sender_id=? AND receiver_id=u.id))
                              AND is_deleted=0 ORDER BY id DESC LIMIT 1) as last_msg,
                             (SELECT created_at FROM messages WHERE ((sender_id=u.id AND receiver_id=?) OR (sender_id=? AND receiver_id=u.id))
                              AND is_deleted=0 ORDER BY id DESC LIMIT 1) as last_time,
                             (SELECT COUNT(*) FROM messages WHERE sender_id=u.id AND receiver_id=? AND status!='seen' AND is_deleted=0) as unread
                             FROM users u
                             JOIN friendships f ON f.friend_id=u.id
                             WHERE f.user_id=?
                             ORDER BY last_time DESC NULLS LAST LIMIT 8""",
                          (uid, uid, uid, uid, uid, uid)).fetchall()

    recent_calls = conn.execute("""SELECT c.*, u.full_name, u.profile_pic, u.username FROM calls c
                                   JOIN users u ON (u.id = CASE WHEN c.caller_id=? THEN c.receiver_id ELSE c.caller_id END)
                                   WHERE c.caller_id=? OR c.receiver_id=?
                                   ORDER BY c.id DESC LIMIT 5""", (uid, uid, uid)).fetchall()

    conn.close()
    return render_template('dashboard.html', user=user, total_friends=total_friends,
                           pending_requests=pending_requests, unread_msgs=unread_msgs,
                           unread_notifs=unread_notifs, friends=friends,
                           recent=recent, recent_calls=recent_calls)

@app.route('/search')
@login_required
def search():
    q = request.args.get('q', '').strip().lower()
    uid = session['user_id']
    results = []
    if q:
        conn = get_db()
        rows = conn.execute("""SELECT * FROM users WHERE (username LIKE ? OR full_name LIKE ?) AND id!=?
                               LIMIT 20""", (f'%{q}%', f'%{q}%', uid)).fetchall()
        for r in rows:
            req = conn.execute("SELECT status FROM friend_requests WHERE sender_id=? AND receiver_id=?",
                               (uid, r['id'])).fetchone()
            in_req = conn.execute("SELECT status FROM friend_requests WHERE sender_id=? AND receiver_id=?",
                                  (r['id'], uid)).fetchone()
            friend = are_friends(uid, r['id'])
            results.append({
                'id': r['id'], 'full_name': r['full_name'], 'username': r['username'],
                'bio': r['bio'], 'profile_pic': r['profile_pic'], 'is_online': r['is_online'],
                'friend': friend,
                'request_sent': req is not None and req['status']=='pending',
                'request_received': in_req is not None and in_req['status']=='pending',
            })
        conn.close()
    user = current_user()
    return render_template('search.html', user=user, results=results, q=q)

@app.route('/friends')
@login_required
def friends():
    uid = session['user_id']
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    rows = conn.execute("""SELECT u.* FROM users u JOIN friendships f ON f.friend_id=u.id
                           WHERE f.user_id=? ORDER BY u.is_online DESC, u.full_name""", (uid,)).fetchall()
    pending = conn.execute("""SELECT fr.*, u.full_name, u.username, u.profile_pic FROM friend_requests fr
                              JOIN users u ON u.id=fr.sender_id
                              WHERE fr.receiver_id=? AND fr.status='pending'""", (uid,)).fetchall()
    sent = conn.execute("""SELECT fr.*, u.full_name, u.username, u.profile_pic FROM friend_requests fr
                           JOIN users u ON u.id=fr.receiver_id
                           WHERE fr.sender_id=? AND fr.status='pending'""", (uid,)).fetchall()
    conn.close()
    return render_template('friends.html', user=user, friends=rows, pending=pending, sent=sent)

@app.route('/api/friend-request/send', methods=['POST'])
@login_required
def send_friend_request():
    uid = session['user_id']
    target = request.json.get('user_id')
    if target == uid:
        return jsonify(ok=False, error='Cannot send request to yourself'), 400
    if are_friends(uid, target):
        return jsonify(ok=False, error='Already friends'), 400
    if is_blocked(uid, target):
        return jsonify(ok=False, error='Cannot send request'), 400
    conn = get_db()
    existing = conn.execute("SELECT * FROM friend_requests WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?)",
                            (uid, target, target, uid)).fetchone()
    if existing:
        if existing['status'] == 'pending':
            conn.close()
            return jsonify(ok=False, error='Request already pending'), 400
        conn.execute("DELETE FROM friend_requests WHERE id=?", (existing['id'],))
    conn.execute("INSERT INTO friend_requests (sender_id, receiver_id) VALUES (?, ?)", (uid, target))
    sender = conn.execute("SELECT full_name, username FROM users WHERE id=?", (uid,)).fetchone()
    conn.execute("INSERT INTO notifications (user_id, type, content, link) VALUES (?, 'friend_request', ?, '/friends')",
                 (target, f"{sender['full_name']} sent you a friend request."))
    conn.commit()
    conn.close()
    socketio.emit('friend_request', {
        'from_id': uid, 'from_name': sender['full_name'],
        'from_username': sender['username']
    }, to=f'user_{target}')
    return jsonify(ok=True)

@app.route('/api/friend-request/respond', methods=['POST'])
@login_required
def respond_friend_request():
    uid = session['user_id']
    rid = request.json.get('request_id')
    action = request.json.get('action')  # accept, reject, block
    conn = get_db()
    req = conn.execute("SELECT * FROM friend_requests WHERE id=? AND receiver_id=?", (rid, uid)).fetchone()
    if not req:
        conn.close()
        return jsonify(ok=False, error='Request not found'), 404
    if action == 'accept':
        conn.execute("UPDATE friend_requests SET status='accepted' WHERE id=?", (rid,))
        conn.execute("INSERT OR IGNORE INTO friendships (user_id, friend_id) VALUES (?, ?)", (uid, req['sender_id']))
        conn.execute("INSERT OR IGNORE INTO friendships (user_id, friend_id) VALUES (?, ?)", (req['sender_id'], uid))
        conn.execute("""INSERT INTO notifications (user_id, type, content, link)
                        VALUES (?, 'friend_accept', 'Your friend request was accepted.', '/friends')""",
                     (req['sender_id'],))
        conn.commit()
        socketio.emit('friend_accepted', {'by_id': uid}, to=f'user_{req["sender_id"]}')
    elif action == 'reject':
        conn.execute("UPDATE friend_requests SET status='rejected' WHERE id=?", (rid,))
        conn.commit()
    elif action == 'block':
        conn.execute("UPDATE friend_requests SET status='rejected' WHERE id=?", (rid,))
        conn.execute("INSERT OR IGNORE INTO blocked_users (user_id, blocked_id) VALUES (?, ?)", (uid, req['sender_id']))
        conn.commit()
    conn.close()
    return jsonify(ok=True)

@app.route('/api/friend-request/cancel', methods=['POST'])
@login_required
def cancel_request():
    uid = session['user_id']
    rid = request.json.get('request_id')
    conn = get_db()
    conn.execute("DELETE FROM friend_requests WHERE id=? AND sender_id=?", (rid, uid))
    conn.commit()
    conn.close()
    return jsonify(ok=True)

@app.route('/chat/<int:friend_id>')
@login_required
def chat(friend_id):
    uid = session['user_id']
    if not are_friends(uid, friend_id):
        flash('You can only chat with accepted friends.', 'error')
        return redirect(url_for('friends'))
    if is_blocked(uid, friend_id):
        flash('You cannot chat with this user.', 'error')
        return redirect(url_for('friends'))
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    friend = conn.execute("SELECT * FROM users WHERE id=?", (friend_id,)).fetchone()
    if not friend:
        conn.close()
        return redirect(url_for('friends'))
    # mark incoming messages as seen
    conn.execute("UPDATE messages SET status='seen' WHERE sender_id=? AND receiver_id=? AND status!='seen'",
                 (friend_id, uid))
    conn.commit()
    conn.close()
    return render_template('chat.html', user=user, friend=friend)

@app.route('/api/messages/<int:friend_id>')
@login_required
def get_messages(friend_id):
    uid = session['user_id']
    if not are_friends(uid, friend_id):
        return jsonify(ok=False, error='Not friends'), 403
    page = int(request.args.get('page', 1))
    per_page = 30
    offset = (page - 1) * per_page
    conn = get_db()
    rows = conn.execute("""SELECT * FROM messages
                           WHERE ((sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?))
                           AND is_deleted=0
                           ORDER BY id DESC LIMIT ? OFFSET ?""",
                        (uid, friend_id, friend_id, uid, per_page, offset)).fetchall()
    conn.close()
    msgs = [dict(r) for r in reversed(rows)]
    return jsonify(ok=True, messages=msgs, page=page, has_more=len(rows)==per_page)

@app.route('/api/messages/send', methods=['POST'])
@login_required
def send_message():
    uid = session['user_id']
    data = request.json
    receiver = data.get('receiver_id')
    content = (data.get('content') or '').strip()
    msg_type = data.get('message_type', 'text')
    file_url = data.get('file_url')
    reply_to = data.get('reply_to')

    if not receiver or (not content and not file_url):
        return jsonify(ok=False, error='Empty message'), 400
    if not are_friends(uid, receiver) or is_blocked(uid, receiver):
        return jsonify(ok=False, error='Not allowed'), 403

    conn = get_db()
    cur = conn.execute("""INSERT INTO messages (sender_id, receiver_id, content, message_type, file_url, reply_to, status)
                          VALUES (?, ?, ?, ?, ?, ?, 'sent')""",
                       (uid, receiver, content, msg_type, file_url, reply_to))
    mid = cur.lastrowid
    conn.execute("""INSERT INTO notifications (user_id, type, content, link)
                    VALUES (?, 'message', ?, ?)""",
                 (receiver, content[:80] if content else 'Sent a file', f'/chat/{uid}'))
    conn.commit()
    msg = dict(conn.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone())
    conn.close()

    socketio.emit('new_message', msg, to=f'user_{receiver}')
    socketio.emit('message_sent', msg, to=f'user_{uid}')
    return jsonify(ok=True, message=msg)

@app.route('/api/messages/<int:mid>', methods=['PUT', 'DELETE'])
@login_required
def edit_or_delete_message(mid):
    uid = session['user_id']
    conn = get_db()
    msg = conn.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
    if not msg or msg['sender_id'] != uid:
        conn.close()
        return jsonify(ok=False), 403
    if request.method == 'PUT':
        content = (request.json.get('content') or '').strip()
        if not content:
            conn.close()
            return jsonify(ok=False), 400
        conn.execute("UPDATE messages SET content=?, is_edited=1 WHERE id=?", (content, mid))
        conn.commit()
        conn.close()
        socketio.emit('message_edited', {'id': mid, 'content': content}, to=f'user_{msg["receiver_id"]}')
        return jsonify(ok=True)
    else:
        conn.execute("UPDATE messages SET is_deleted=1, content='' WHERE id=?", (mid,))
        conn.commit()
        conn.close()
        socketio.emit('message_deleted', {'id': mid}, to=f'user_{msg["receiver_id"]}')
        return jsonify(ok=True)

@app.route('/api/messages/mark-seen', methods=['POST'])
@login_required
def mark_seen():
    uid = session['user_id']
    friend = request.json.get('friend_id')
    conn = get_db()
    conn.execute("UPDATE messages SET status='seen' WHERE sender_id=? AND receiver_id=? AND status!='seen'",
                 (friend, uid))
    conn.commit()
    conn.close()
    socketio.emit('messages_seen', {'by': uid}, to=f'user_{friend}')
    return jsonify(ok=True)

@app.route('/api/messages/search')
@login_required
def search_messages():
    uid = session['user_id']
    q = request.args.get('q', '').strip()
    friend = int(request.args.get('friend_id', 0))
    if not q or not friend or not are_friends(uid, friend):
        return jsonify(ok=True, results=[])
    conn = get_db()
    rows = conn.execute("""SELECT * FROM messages
                           WHERE ((sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?))
                           AND content LIKE ? AND is_deleted=0
                           ORDER BY id DESC LIMIT 50""",
                        (uid, friend, friend, uid, f'%{q}%')).fetchall()
    conn.close()
    return jsonify(ok=True, results=[dict(r) for r in rows])

@app.route('/api/messages/clear', methods=['POST'])
@login_required
def clear_chat():
    uid = session['user_id']
    friend = request.json.get('friend_id')
    conn = get_db()
    conn.execute("UPDATE messages SET is_deleted=1 WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?)",
                 (uid, friend, friend, uid))
    conn.commit()
    conn.close()
    socketio.emit('chat_cleared', {'by': uid}, to=f'user_{friend}')
    return jsonify(ok=True)

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    f = request.files.get('file')
    if not f or not f.filename:
        return jsonify(ok=False, error='No file'), 400
    ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else ''
    if ext not in app.config['ALLOWED_EXTENSIONS']:
        return jsonify(ok=False, error='File type not allowed'), 400
    fname = f"{uuid.uuid4().hex}_{secure_filename(f.filename)}"
    path = os.path.join(app.config['UPLOAD_FOLDER'], fname)
    f.save(path)
    return jsonify(ok=True, url=f'/static/uploads/{fname}', filename=f.filename, ext=ext)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    uid = session['user_id']
    conn = get_db()
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        bio = request.form.get('bio', '').strip()
        email_private = 1 if request.form.get('email_private') else 0
        if len(full_name) >= 2:
            conn.execute("UPDATE users SET full_name=?, bio=?, email_private=? WHERE id=?",
                         (full_name, bio, email_private, uid))
            file = request.files.get('profile_pic')
            if file and file.filename:
                ext = file.filename.rsplit('.', 1)[-1].lower()
                if ext in {'png', 'jpg', 'jpeg', 'gif', 'webp'}:
                    fname = f"{uuid.uuid4().hex}.{ext}"
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], fname))
                    conn.execute("UPDATE users SET profile_pic=? WHERE id=?", (fname, uid))
            conn.commit()
            flash('Profile updated', 'success')
    user = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    return render_template('profile.html', user=user)

@app.route('/api/change-password', methods=['POST'])
@login_required
def change_password():
    uid = session['user_id']
    old = request.json.get('old_password', '')
    new = request.json.get('new_password', '')
    if len(new) < 8:
        return jsonify(ok=False, error='Password must be 8+ chars'), 400
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not check_password_hash(user['password_hash'], old):
        conn.close()
        return jsonify(ok=False, error='Current password incorrect'), 400
    conn.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(new), uid))
    conn.commit()
    conn.close()
    return jsonify(ok=True)

@app.route('/settings')
@login_required
def settings():
    uid = session['user_id']
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    blocked = conn.execute("""SELECT u.* FROM users u JOIN blocked_users b ON b.blocked_id=u.id
                              WHERE b.user_id=?""", (uid,)).fetchall()
    conn.close()
    return render_template('settings.html', user=user, blocked=blocked)

@app.route('/api/unblock', methods=['POST'])
@login_required
def unblock():
    uid = session['user_id']
    bid = request.json.get('user_id')
    conn = get_db()
    conn.execute("DELETE FROM blocked_users WHERE user_id=? AND blocked_id=?", (uid, bid))
    conn.commit()
    conn.close()
    return jsonify(ok=True)

@app.route('/api/block', methods=['POST'])
@login_required
def block():
    uid = session['user_id']
    bid = request.json.get('user_id')
    conn = get_db()
    conn.execute("INSERT OR IGNORE INTO blocked_users (user_id, blocked_id) VALUES (?, ?)", (uid, bid))
    conn.commit()
    conn.close()
    return jsonify(ok=True)

@app.route('/calls')
@login_required
def calls():
    uid = session['user_id']
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    rows = conn.execute("""SELECT c.*, u.full_name, u.profile_pic, u.username,
                           CASE WHEN c.caller_id=? THEN 'outgoing' ELSE 'incoming' END as direction
                           FROM calls c
                           JOIN users u ON u.id = CASE WHEN c.caller_id=? THEN c.receiver_id ELSE c.caller_id END
                           WHERE c.caller_id=? OR c.receiver_id=?
                           ORDER BY c.id DESC LIMIT 100""", (uid, uid, uid, uid)).fetchall()
    conn.close()
    return render_template('calls.html', user=user, calls=rows)

@app.route('/api/calls/clear', methods=['POST'])
@login_required
def clear_calls():
    uid = session['user_id']
    conn = get_db()
    conn.execute("DELETE FROM calls WHERE caller_id=? OR receiver_id=?", (uid, uid))
    conn.commit()
    conn.close()
    return jsonify(ok=True)

@app.route('/notifications')
@login_required
def notifications():
    uid = session['user_id']
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    rows = conn.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 100", (uid,)).fetchall()
    conn.close()
    return render_template('notifications.html', user=user, notifications=rows)

@app.route('/api/notifications/<int:nid>/read', methods=['POST'])
@login_required
def read_notification(nid):
    conn = get_db()
    conn.execute("UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?", (nid, session['user_id']))
    conn.commit()
    conn.close()
    return jsonify(ok=True)

@app.route('/api/notifications/clear', methods=['POST'])
@login_required
def clear_notifications():
    conn = get_db()
    conn.execute("DELETE FROM notifications WHERE user_id=?", (session['user_id'],))
    conn.commit()
    conn.close()
    return jsonify(ok=True)

# ========== ADMIN ==========
@app.route('/admin')
@admin_required
def admin_panel():
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session['user_id'],)).fetchone()
    total_users = conn.execute("SELECT COUNT(*) c FROM users WHERE is_admin=0").fetchone()['c']
    online = conn.execute("SELECT COUNT(*) c FROM users WHERE is_online=1 AND is_admin=0").fetchone()['c']
    blocked = conn.execute("SELECT COUNT(*) c FROM users WHERE is_blocked=1").fetchone()['c']
    all_users = conn.execute("SELECT * FROM users WHERE is_admin=0 ORDER BY id DESC").fetchall()
    reports = conn.execute("""SELECT r.*, u1.username as reporter, u2.username as reported
                              FROM reports r JOIN users u1 ON u1.id=r.reporter_id
                              JOIN users u2 ON u2.id=r.reported_id ORDER BY r.id DESC""").fetchall()
    conn.close()
    return render_template('admin.html', user=user, total_users=total_users, online=online,
                           blocked=blocked, all_users=all_users, reports=reports)

@app.route('/api/admin/toggle-block/<int:uid>', methods=['POST'])
@admin_required
def admin_toggle_block(uid):
    conn = get_db()
    u = conn.execute("SELECT is_blocked FROM users WHERE id=?", (uid,)).fetchone()
    conn.execute("UPDATE users SET is_blocked=? WHERE id=?", (0 if u['is_blocked'] else 1, uid))
    conn.commit()
    conn.close()
    return jsonify(ok=True)

@app.route('/api/admin/report-resolve/<int:rid>', methods=['POST'])
@admin_required
def admin_resolve_report(rid):
    conn = get_db()
    conn.execute("UPDATE reports SET status='resolved' WHERE id=?", (rid,))
    conn.commit()
    conn.close()
    return jsonify(ok=True)

@app.route('/api/report', methods=['POST'])
@login_required
def report_user():
    uid = session['user_id']
    target = request.json.get('user_id')
    reason = request.json.get('reason', '').strip()
    if not reason or target == uid:
        return jsonify(ok=False), 400
    conn = get_db()
    conn.execute("INSERT INTO reports (reporter_id, reported_id, reason) VALUES (?, ?, ?)",
                 (uid, target, reason))
    conn.commit()
    conn.close()
    return jsonify(ok=True)

@app.route('/api/notifications/list')
@login_required
def api_notifications():
    uid = session['user_id']
    conn = get_db()
    rows = conn.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 30", (uid,)).fetchall()
    unread = conn.execute("SELECT COUNT(*) c FROM notifications WHERE user_id=? AND is_read=0", (uid,)).fetchone()['c']
    conn.close()
    return jsonify(ok=True, notifications=[dict(r) for r in rows], unread=unread)

# ========== SOCKET.IO ==========
online_users = set()

@socketio.on('connect')
def on_connect():
    uid = session.get('user_id')
    if not uid:
        return False
    online_users.add(uid)
    join_room(f'user_{uid}')
    conn = get_db()
    conn.execute("UPDATE users SET is_online=1 WHERE id=?", (uid,))
    conn.commit()
    conn.close()
    socketio.emit('presence', {'user_id': uid, 'online': True}, broadcast=True)

@socketio.on('disconnect')
def on_disconnect():
    uid = session.get('user_id')
    if uid and uid in online_users:
        online_users.discard(uid)
        conn = get_db()
        conn.execute("UPDATE users SET is_online=0, last_seen=CURRENT_TIMESTAMP WHERE id=?", (uid,))
        conn.commit()
        conn.close()
        socketio.emit('presence', {'user_id': uid, 'online': False}, broadcast=True)

@socketio.on('typing')
def on_typing(data):
    uid = session.get('user_id')
    if not uid: return
    to = data.get('to')
    if to and are_friends(uid, to):
        socketio.emit('typing', {'from': uid}, to=f'user_{to}')

@socketio.on('stop_typing')
def on_stop_typing(data):
    uid = session.get('user_id')
    if not uid: return
    to = data.get('to')
    if to:
        socketio.emit('stop_typing', {'from': uid}, to=f'user_{to}')

# WebRTC signaling
@socketio.on('call_user')
def on_call_user(data):
    uid = session.get('user_id')
    if not uid: return
    to = data.get('to')
    if not are_friends(uid, to) or is_blocked(uid, to):
        emit('call_error', {'error': 'Not allowed'})
        return
    conn = get_db()
    caller = conn.execute("SELECT full_name, username, profile_pic FROM users WHERE id=?", (uid,)).fetchone()
    cur = conn.execute("INSERT INTO calls (caller_id, receiver_id, call_type, status) VALUES (?, ?, ?, 'missed')",
                       (uid, to, data.get('type', 'audio')))
    call_id = cur.lastrowid
    conn.commit()
    conn.close()
    socketio.emit('incoming_call', {
        'from': uid, 'from_name': caller['full_name'],
        'from_username': caller['username'], 'from_pic': caller['profile_pic'],
        'call_id': call_id, 'type': data.get('type', 'audio'),
        'offer': data.get('offer')
    }, to=f'user_{to}')

@socketio.on('answer_call')
def on_answer_call(data):
    uid = session.get('user_id')
    if not uid: return
    to = data.get('to')
    call_id = data.get('call_id')
    conn = get_db()
    conn.execute("UPDATE calls SET status='answered' WHERE id=?", (call_id,))
    conn.commit()
    conn.close()
    socketio.emit('call_answered', {'answer': data.get('answer'), 'from': uid}, to=f'user_{to}')

@socketio.on('ice_candidate')
def on_ice(data):
    uid = session.get('user_id')
    if not uid: return
    to = data.get('to')
    socketio.emit('ice_candidate', {'candidate': data.get('candidate'), 'from': uid}, to=f'user_{to}')

@socketio.on('reject_call')
def on_reject(data):
    uid = session.get('user_id')
    to = data.get('to')
    call_id = data.get('call_id')
    conn = get_db()
    conn.execute("UPDATE calls SET status='rejected' WHERE id=?", (call_id,))
    conn.commit()
    conn.close()
    socketio.emit('call_rejected', {'from': uid}, to=f'user_{to}')

@socketio.on('end_call')
def on_end(data):
    uid = session.get('user_id')
    to = data.get('to')
    call_id = data.get('call_id')
    duration = data.get('duration', 0)
    conn = get_db()
    conn.execute("UPDATE calls SET status='completed', duration=? WHERE id=?", (duration, call_id))
    conn.commit()
    conn.close()
    socketio.emit('call_ended', {'from': uid}, to=f'user_{to}')

# ========== MAIN ==========
if __name__ == '__main__':
    init_db()
    print("\n" + "="*60)
    print("  ConnectX is starting...")
    print("  Open: http://127.0.0.1:5000")
    print(f"  Admin: {app.config['ADMIN_USERNAME']} / {app.config['ADMIN_PASSWORD']}")
    print("="*60 + "\n")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)