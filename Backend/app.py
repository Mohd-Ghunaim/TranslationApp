from flask import Flask, request, jsonify
from flask_cors import CORS
from googletrans import Translator
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
CORS(app)

def create_users_table():
  conn = sqlite3.connect("users.db")
  cursor = conn.cursor()

  cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT,
      password TEXT NOT NULL
    )
  """)

  conn.commit()
  conn.close()

create_users_table()

@app.route("/translate", methods=['POST'])
def translate():
  data = request.get_json()
  text = data.get("text")
  source_lang = data.get("source")
  target_lang = data.get("target")

  translator = Translator()
  translated = translator.translate(text, src=source_lang, dest=target_lang)

  return {"translated_text": translated.text}

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
      "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
      (username, email, hashed_password)
    )

    conn.commit()
    conn.close()

    return jsonify({"message": "Signup successful"})

  except sqlite3.IntegrityError:
    return jsonify({"error": "Username already exists"}), 400

@app.route("/login", methods=['POST'])
def login():
  data = request.get_json()
  username = data.get("username")
  password = data.get("password")

  conn = sqlite3.connect("users.db")
  cursor = conn.cursor()

  cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
  user = cursor.fetchone()

  conn.close()

  if user and check_password_hash(user[0], password):
    return jsonify({"message": "Login successful"})
  else:
    return jsonify({"error": "Invalid username or password"}), 401


if __name__ == "__main__":
  app.run(debug=True)