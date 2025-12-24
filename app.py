from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import random
import smtplib
from email.mime.text import MIMEText
import os
import mysql.connector
from dotenv import load_dotenv

# Load .env variables
load_dotenv()

app = Flask(__name__)

def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME")
    )

# ----------------- EMAIL -----------------
def send_email(to_email, subject, body):
    sender_email = os.getenv("EMAIL_SENDER")
    sender_password = os.getenv("EMAIL_PASSWORD")

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = to_email

    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(sender_email, sender_password)
    server.send_message(msg)
    server.quit()

# ----------------- HOME -----------------
@app.route("/")
def home():
    return "Flask is running!"

# ----------------- SIGNUP -----------------
@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"message": "Email and password required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
    if cursor.fetchone():
        cursor.close()
        conn.close()
        return jsonify({"message": "User already exists"}), 400

    token = str(random.randint(100000, 999999))
    expiration = datetime.now() + timedelta(minutes=10)

    cursor.execute("""
        INSERT INTO users (email, password, verification_token, verification_expiration)
        VALUES (%s, %s, %s, %s)
    """, (email, generate_password_hash(password), token, expiration))

    conn.commit()
    cursor.close()
    conn.close()

    send_email(
        email,
        "Verify Account",
        f"Your verification token is {token}. It expires in 10 minutes."
    )

    return jsonify({"message": "Signup successful"}), 201

# ----------------- VERIFY -----------------
@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json()
    email = data.get("email")
    token = str(data.get("token"))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        "SELECT * FROM users WHERE email=%s AND verification_token=%s",
        (email, token)
    )
    user = cursor.fetchone()

    if not user:
        cursor.close()
        conn.close()
        return jsonify({"message": "Invalid token"}), 400

    if datetime.now() > user["verification_expiration"]:
        cursor.close()
        conn.close()
        return jsonify({"message": "Token expired"}), 400

    cursor.execute("""
        UPDATE users
        SET verified=TRUE,
            verification_token=NULL,
            verification_expiration=NULL
        WHERE email=%s
    """, (email,))

    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "Account verified"})

# ----------------- LOGIN -----------------
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if not user:
        return jsonify({"message": "User not found"}), 404
    if not user["verified"]:
        return jsonify({"message": "Account not verified"}), 403
    if not check_password_hash(user["password"], password):
        return jsonify({"message": "Wrong password"}), 400

    return jsonify({"message": "Login successful"})

# ----------------- REQUEST RESET -----------------
@app.route("/request-reset", methods=["POST"])
def request_reset():
    data = request.get_json()
    email = data.get("email")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        conn.close()
        return jsonify({"message": "User not found"}), 404

    reset_token = str(random.randint(100000, 999999))
    reset_expiration = datetime.now() + timedelta(minutes=10)

    cursor.execute("""
        UPDATE users
        SET reset_token=%s, reset_expiration=%s
        WHERE email=%s
    """, (reset_token, reset_expiration, email))

    conn.commit()
    cursor.close()
    conn.close()

    first_name = email.split("@")[0].split(".")[0].capitalize()

    send_email(
        email,
        "Password Reset",
        f"""Hello {first_name},

You can now change your password.

Reset Token: {reset_token}
This token expires in 10 minutes.
"""
    )

    return jsonify({"message": "Reset token sent"})

# ----------------- RESET PASSWORD -----------------
@app.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json()
    token = str(data.get("token"))
    new_password = data.get("new_password")

    if not token or not new_password:
        return jsonify({"message": "Token and new password required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE reset_token=%s", (token,))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        conn.close()
        return jsonify({"message": "Invalid reset token"}), 400

    if datetime.now() > user["reset_expiration"]:
        cursor.close()
        conn.close()
        return jsonify({"message": "Reset token expired"}), 400

    cursor.execute("""
        UPDATE users
        SET password=%s,
            reset_token=NULL,
            reset_expiration=NULL
        WHERE id=%s
    """, (generate_password_hash(new_password), user["id"]))

    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "Password reset successful"})

if __name__ == "__main__":
    app.run(debug=True)
