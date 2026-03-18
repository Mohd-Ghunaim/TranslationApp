from flask import Flask, request, jsonify, render_template, session, Response
from flask_cors import CORS
from googletrans import Translator
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from dotenv import load_dotenv
import csv
from logger import login_logger, translation_logger, error_logger
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

load_dotenv()

app = Flask(__name__)
CORS(app)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

limiter = Limiter(app=app, key_func=get_remote_address)

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

@app.route("/")
def home():
  return render_template("login.html")

@app.route("/signup-page")
def signup_page():
  return render_template("signup.html")


@app.route("/translator")
def translator_page():
  return render_template("index.html")

@app.route("/translate", methods=['POST'])
def translate():
  data = request.get_json()
  text = data.get("text")
  source_lang = data.get("source")
  target_lang = data.get("target")

  username = session.get("username")
  user_id = session.get("user_id")

  if user_id is None:     
    error_logger.error("User not logged in")
    return jsonify({"error": "User not logged in"}), 401 

  translator = Translator()
  translated = translator.translate(text, src=source_lang, dest=target_lang)

  log_translation(user_id, text, source_lang, target_lang)
  translation_logger.info(f"User {username} translated text from {source_lang} to {target_lang}")
  
  return {"translated_text": translated.text}

def log_translation(user_id, text, source, target):
  conn = sqlite3.connect("users.db")
  cursor = conn.cursor()
  cursor.execute("""
    INSERT INTO translation_logs (user_id, input_text, source, target)
    VALUES (?, ?, ?, ?)
  """, (user_id, text, source, target))
  conn.commit()
  conn.close()

@app.route("/signup", methods=['POST'])
def signup():
  data = request.get_json()
  username = data.get("username")
  email = data.get("email")
  password = data.get("password")

  if not username or not password:
    return jsonify({"error": "Username and password required"}), 400

  hashed_password = generate_password_hash(password)

  try:
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute(
      "INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, 0)",
      (username, email, hashed_password)
    )

    conn.commit()
    conn.close()

    return jsonify({"message": "Signup successful"})

  except sqlite3.IntegrityError:
    error_logger.error(f"User {username} already exists")
    return jsonify({"error": "Username already exists"}), 400

@app.route("/login", methods=['POST'])
@limiter.limit("10 per minute")
def login():
  data = request.get_json()
  username = data.get("username")
  password = data.get("password")

  conn = sqlite3.connect("users.db")
  cursor = conn.cursor()

  cursor.execute(
    "SELECT id, password, is_admin FROM users WHERE username = ?",
    (username,)
  )
  user = cursor.fetchone()
  conn.close()

  if user and check_password_hash(user[1], password):

    login_logger.info(f"User {username} logged in")

    session["user_id"] = user[0]
    session["username"] = username
    session["is_admin"] = user[2]

    if user[2] == 1:
      return jsonify({"redirect": "/admin-dashboard"})
    else:
      return jsonify({"redirect": "/translator"})
    
  else:
    error_logger.error(f"Failed login attempt for user {username}")
    return jsonify({"error": "Invalid username or password"}), 401
  
@app.route("/logout", methods=['POST'])
def logout():
  login_logger.info(f"User {session.get('username')} logged out") 
  session.clear()
  return jsonify({"message": "Logout successful"})

@app.route("/admin")
def admin_page():
  if not session.get("user_id"):
    return "Unauthorized", 403

  if session.get("is_admin") != 1:
    return "Forbidden", 403

  return render_template("adminindex.html")


@app.route("/admin-dashboard")
def admin_dashboard():
  if session.get("is_admin") != 1:
    return "Unauthorized", 403

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

@app.route("/users")
def users_page():
  if not session.get("user_id"):
    return "Unauthorized", 403

  if session.get("is_admin") != 1:
    return "Forbidden", 403

  return render_template("users.html")

@app.route("/admin/users-data")
def users_data():
  if session.get("is_admin") != 1:
    return "Forbidden", 403

  conn = sqlite3.connect("users.db")
  cursor = conn.cursor()

  cursor.execute("SELECT id, username, is_admin FROM users")
  rows = cursor.fetchall()
  conn.close()

  users = []
  for row in rows:
    users.append({
      "id": row[0],
      "username": row[1],
      "is_admin": row[2]
    })

  return jsonify(users)

@app.route("/admin/update-user", methods=["POST"])
def update_user():
  if session.get("is_admin") != 1:
    return "Forbidden", 403

  data = request.get_json()
  user_id = data.get("id")
  new_role = data.get("is_admin")

  conn = sqlite3.connect("users.db")
  cursor = conn.cursor()
  cursor.execute(
    "UPDATE users SET is_admin = ? WHERE id = ?",
    (new_role, user_id)
  )
  conn.commit()
  conn.close()

  return jsonify({"message": "Updated"})

@app.route("/reports")
def reports():
  if session.get("is_admin") != 1:
    return "forbidden", 403

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

  return render_template("reports.html", logs=logs, page=page)

@app.route("/download-logs")
def download_logs():
  if session.get("is_admin") != 1:
    return "Unauthorized", 403

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
    yield "\ufeff"
    yield "username,input_text,source,target,timestamp\n"
    for row in rows:
      yield f'"{row[0]}","{row[1]}","{row[2]}","{row[3]}","{row[4]}"\n'

  return Response(
    generate(),
    mimetype="text/csv; charset=utf-8",
    headers={"Content-Disposition": "attachment; filename=translation_logs.csv"}
  )

if __name__ == "__main__":
  app.run(debug=True)