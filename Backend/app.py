from flask import Flask, request, jsonify, render_template, Response
from flask_cors import CORS
from googletrans import Translator
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from dotenv import load_dotenv
from logger import login_logger, translation_logger, error_logger
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from bleach import clean
import jwt
from datetime import datetime, timedelta
from functools import wraps
import traceback

load_dotenv()

app = Flask(__name__)
CORS(app)

# ---------------- Config ----------------
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY") or "dev_secret_key"
JWT_SECRET = app.config["SECRET_KEY"]
JWT_ALGORITHM = "HS256"
JWT_EXP_MINUTES = 60

limiter = Limiter(app=app, key_func=get_remote_address)

# ---------------- Database Setup ----------------
def create_users_table():
  conn = sqlite3.connect("users.db")
  cursor = conn.cursor()
  cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT,
      password TEXT NOT NULL,
      is_admin INTEGER DEFAULT 0
    )
  """)
  cursor.execute("""
    CREATE TABLE IF NOT EXISTS translation_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      input_text TEXT,
      source TEXT,
      target TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  """)
  conn.commit()
  conn.close()

create_users_table()

# ---------------- JWT Helpers ----------------
def token_required(f):
  @wraps(f)
  def decorated(*args, **kwargs):
    token = None
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
      token = auth_header.split(" ")[1]

    if not token:
      return jsonify({"error": "Token missing"}), 401

    try:
      data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
      request.user = {
        "user_id": data["user_id"],
        "username": data["username"],
        "is_admin": data["is_admin"]
      }
    except jwt.ExpiredSignatureError:
      return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
      return jsonify({"error": "Invalid token"}), 401
    except Exception as e:
      print("JWT decode error:", e)
      return jsonify({"error": "Token decode error"}), 401

    return f(*args, **kwargs)
  return decorated

def admin_required(f):
  @wraps(f)
  @token_required
  def decorated(*args, **kwargs):
    if request.user["is_admin"] != 1:
      return jsonify({"error": "Admin required"}), 403
    return f(*args, **kwargs)
  return decorated

def generate_token(user):
  try:
    print("Generating token for user:", user)
    payload = {
      "user_id": user[0],
      "username": user[1],
      "is_admin": user[2],
      "exp": datetime.utcnow() + timedelta(minutes=JWT_EXP_MINUTES)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    if isinstance(token, bytes):
      token = token.decode("utf-8")
    return token
  except Exception as e:
    print("Error generating token:", e)
    return None

# ---------------- Routes ----------------
@app.route("/")
def home():
  return render_template("login.html")

@app.route("/signup-page")
def signup_page():
  return render_template("signup.html")

@app.route("/translator")
def translator_page():
  return render_template("index.html")

@app.route("/users")
def users_page():
  return render_template("users.html")

@app.route("/reports-page")
def reports_page():
  return render_template("reportspage.html")

@app.route("/admin")
def admin_page():
  return render_template("adminindex.html")

# ---------------- Auth ----------------
@app.route("/signup", methods=["POST"])
def signup():
  try:
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not username or not password:
      return jsonify({"error": "Username and password required"}), 400

    hashed_password = generate_password_hash(password)

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(
      "INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, 0)",
      (username, email, hashed_password)
    )
    conn.commit()
    conn.close()
    return jsonify({"message": "Signup successful"})
  except Exception:
    print("Signup error:\n", traceback.format_exc())
    return jsonify({"error": "Internal server error"}), 500

@app.route("/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
  try:
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
      return jsonify({"error": "Username and password required"}), 400

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password, is_admin FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user[2], password):  # user[2] is password
      # generate token using correct indices: id, username, is_admin
      token = generate_token((user[0], user[1], user[3]))
      if not token:
        return jsonify({"error": "Token generation failed"}), 500
      login_logger.info(f"User {username} logged in")
      return jsonify({"token": token, "is_admin": user[3]})
    else:
      return jsonify({"error": "Invalid username or password"}), 401
  except Exception:
    print("Login error:\n", traceback.format_exc())
    return jsonify({"error": "Internal server error"}), 500

# ---------------- Translator ----------------
@app.route("/translate", methods=["POST"])
@limiter.limit("30 per minute")
@token_required
def translate():
  try:
    data = request.get_json()
    raw_text = data.get("text")
    source_lang = data.get("source")
    target_lang = data.get("target")

    text = clean(raw_text)
    source_lang = clean(source_lang)
    target_lang = clean(target_lang)

    if not text or len(text) > 5000:
      return jsonify({"error": "Invalid input"}), 400

    translator = Translator()
    translated = translator.translate(text, src=source_lang, dest=target_lang)
    log_translation(request.user["user_id"], text, source_lang, target_lang)
    translation_logger.info(f"User {request.user['username']} translated from {source_lang} to {target_lang}")
    return {"translated_text": translated.text}
  except Exception:
    print("Translate error:\n", traceback.format_exc())
    return jsonify({"error": "Internal server error"}), 500

def log_translation(user_id, text, source, target):
  conn = sqlite3.connect("users.db")
  cursor = conn.cursor()
  cursor.execute("""
    INSERT INTO translation_logs (user_id, input_text, source, target)
    VALUES (?, ?, ?, ?)
  """, (user_id, text, source, target))
  conn.commit()
  conn.close()

# ---------------- Admin Routes ----------------
@app.route("/admin/users-data")
@admin_required
def users_data():
  try:
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, is_admin FROM users")
    rows = cursor.fetchall()
    conn.close()
    users = [{"id": r[0], "username": r[1], "is_admin": r[2]} for r in rows]
    return jsonify(users)
  except Exception:
    print("Users data error:\n", traceback.format_exc())
    return jsonify({"error": "Internal server error"}), 500

@app.route("/admin/update-user", methods=["POST"])
@admin_required
def update_user():
  try:
    data = request.get_json()
    user_id = data.get("id")
    new_role = data.get("is_admin")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET is_admin = ? WHERE id = ?", (new_role, user_id))
    conn.commit()
    conn.close()
    return jsonify({"message": "Updated"})
  except Exception:
    print("Update user error:\n", traceback.format_exc())
    return jsonify({"error": "Internal server error"}), 500
  
@app.route("/admin-dashboard")
def admin_dashboard():
  conn = sqlite3.connect("users.db")
  cursor = conn.cursor()

  cursor.execute("SELECT COUNT(*) FROM translation_logs")
  total_translations = cursor.fetchone()[0]

  cursor.execute("""
    SELECT target, COUNT(*) as count
    FROM translation_logs
    GROUP BY target
    ORDER BY count DESC
    LIMIT 1
  """)
  most_used_language = cursor.fetchone()

  cursor.execute("""
    SELECT DATE(timestamp), COUNT(*)
    FROM translation_logs
    GROUP BY DATE(timestamp)
    ORDER BY DATE(timestamp) DESC
  """)
  translations_per_day = cursor.fetchall()

  cursor.execute("""
    SELECT users.username, COUNT(*) as count
    FROM translation_logs
    JOIN users ON translation_logs.user_id = users.id
    GROUP BY users.username
    ORDER BY count DESC
    LIMIT 5
  """)
  top_users = cursor.fetchall()

  conn.close()

  return render_template(
    "admin-dashboard.html",
    total_translations=total_translations,
    most_used_language=most_used_language,
    translations_per_day=translations_per_day,
    top_users=top_users
  )

@app.route("/admin/reports-data")
@admin_required
def reports_data():
  conn = sqlite3.connect("users.db")
  cursor = conn.cursor()

  cursor.execute("""
      SELECT users.username, input_text, source, target, timestamp
      FROM translation_logs
      JOIN users ON translation_logs.user_id = users.id
      ORDER BY timestamp DESC
  """)

  logs = cursor.fetchall()
  conn.close()

  return jsonify(logs)

@app.route("/reports")
@admin_required
def reports():
  # only admin can access
  if request.user["is_admin"] != 1:
    return jsonify({"error": "Forbidden"}), 403

  page = request.args.get("page", 1, type=int)
  per_page = 10
  offset = (page - 1) * per_page

  conn = sqlite3.connect("users.db")
  cursor = conn.cursor()
  cursor.execute("""
    SELECT users.username, translation_logs.input_text,
            translation_logs.source, translation_logs.target,
            translation_logs.timestamp
    FROM translation_logs
    JOIN users ON translation_logs.user_id = users.id
    ORDER BY translation_logs.timestamp DESC
    LIMIT ? OFFSET ?
  """, (per_page, offset))
  logs = cursor.fetchall()
  conn.close()

  return jsonify({
    "logs": logs,
    "page": page
  })

@app.route("/download-logs")
@admin_required
def download_logs():
  try:
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("""
      SELECT users.username,
             translation_logs.input_text,
             translation_logs.source,
             translation_logs.target,
             translation_logs.timestamp
      FROM translation_logs
      JOIN users ON translation_logs.user_id = users.id
      ORDER BY translation_logs.timestamp DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    def generate():
      yield "\ufeff"  # UTF-8 BOM for Excel
      yield "username,input_text,source,target,timestamp\n"

      for row in rows:
        yield f'"{row[0]}","{row[1]}","{row[2]}","{row[3]}","{row[4]}"\n'

    return Response(
      generate(),
      mimetype="text/csv; charset=utf-8",
      headers={
        "Content-Disposition": "attachment; filename=translation_logs.csv"
      }
    )

  except Exception as e:
    print("Download logs error:", e)
    return jsonify({"error": "Internal server error"}), 500
  
@app.route("/users/check-role")
@token_required
def check_role():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT is_admin FROM users WHERE id = ?", (request.user["user_id"],))
    row = cursor.fetchone()
    conn.close()
    is_admin = row[0] if row else 0
    return jsonify({"is_admin": is_admin})

# ---------------- Run App ----------------
if __name__ == "__main__":
  app.run(debug=True)