import os
import sqlite3
from io import BytesIO
from functools import wraps

import boto3
from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, send_file, session
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv(
    "FLASK_SECRET_KEY",
    "development-secret-key"
)

AWS_BUCKET_NAME = os.getenv("AWS_BUCKET_NAME")
AWS_REGION = os.getenv("AWS_REGION")

DATABASE = "users.db"

s3 = boto3.client(
    "s3",
    region_name=AWS_REGION
)


# ============================================================
# DATABASE
# ============================================================

def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():

    connection = get_db()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS backup_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            action TEXT NOT NULL,
            version_id TEXT,
            file_size INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    connection.commit()
    connection.close()


# ============================================================
# HISTORY RECORDING
# ============================================================

def record_backup_action(
    filename,
    action,
    version_id=None,
    file_size=None
):

    connection = get_db()

    connection.execute(
        """
        INSERT INTO backup_history
        (user_id, filename, action, version_id, file_size)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            session["user_id"],
            filename,
            action,
            version_id,
            file_size
        )
    )

    connection.commit()
    connection.close()


# ============================================================
# USER S3 PATH
# ============================================================

def get_user_prefix():
    return f"users/{session['user_id']}/"


def get_user_file_key(filename):
    return get_user_prefix() + filename


# ============================================================
# LOGIN REQUIRED
# ============================================================

def login_required(function):

    @wraps(function)
    def decorated_function(*args, **kwargs):

        if "user_id" not in session:

            flash(
                "Please login to access the dashboard.",
                "error"
            )

            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return decorated_function


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# ============================================================
# REGISTER
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        if not username or not email or not password:

            flash(
                "All fields are required.",
                "error"
            )

            return redirect(url_for("register"))

        if password != confirm_password:

            flash(
                "Passwords do not match.",
                "error"
            )

            return redirect(url_for("register"))

        if len(password) < 6:

            flash(
                "Password must contain at least 6 characters.",
                "error"
            )

            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)

        try:

            connection = get_db()

            connection.execute(
                """
                INSERT INTO users
                (username, email, password)
                VALUES (?, ?, ?)
                """,
                (
                    username,
                    email,
                    hashed_password
                )
            )

            connection.commit()
            connection.close()

            flash(
                "Registration successful! Please login.",
                "success"
            )

            return redirect(url_for("login"))

        except sqlite3.IntegrityError:

            flash(
                "Username or email already exists.",
                "error"
            )

            return redirect(url_for("register"))

    return render_template("register.html")


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        connection = get_db()

        user = connection.execute(
            """
            SELECT *
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        connection.close()

        if user and check_password_hash(
            user["password"],
            password
        ):

            session.clear()

            session["user_id"] = user["id"]
            session["username"] = user["username"]

            flash(
                "Login successful!",
                "success"
            )

            return redirect(url_for("dashboard"))

        flash(
            "Invalid username or password.",
            "error"
        )

        return redirect(url_for("login"))

    return render_template("login.html")


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(url_for("login"))


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
@login_required
def dashboard():

    files = []

    try:

        response = s3.list_objects_v2(
            Bucket=AWS_BUCKET_NAME,
            Prefix=get_user_prefix()
        )

        for obj in response.get("Contents", []):

            display_name = obj["Key"].replace(
                get_user_prefix(),
                "",
                1
            )

            if not display_name:
                continue

            files.append({
                "name": display_name,
                "size": obj["Size"],
                "last_modified": obj["LastModified"]
            })

    except Exception as e:

        flash(
            f"Error loading files: {e}",
            "error"
        )

    return render_template(
        "dashboard.html",
        files=files,
        username=session.get("username")
    )


# ============================================================
# UPLOAD
# ============================================================

@app.route("/upload", methods=["POST"])
@login_required
def upload_file():

    if "file" not in request.files:

        flash(
            "No file selected.",
            "error"
        )

        return redirect(url_for("dashboard"))

    file = request.files["file"]

    if file.filename == "":

        flash(
            "No file selected.",
            "error"
        )

        return redirect(url_for("dashboard"))

    try:

        filename = secure_filename(file.filename)

        if not filename:

            flash(
                "Invalid filename.",
                "error"
            )

            return redirect(url_for("dashboard"))

        s3_key = get_user_file_key(filename)

        # Upload to S3
        s3.upload_fileobj(
            file,
            AWS_BUCKET_NAME,
            s3_key
        )

        # Get uploaded object information
        head = s3.head_object(
            Bucket=AWS_BUCKET_NAME,
            Key=s3_key
        )

        # RECORD HISTORY
        record_backup_action(
            filename=filename,
            action="UPLOAD",
            version_id=head.get("VersionId"),
            file_size=head.get("ContentLength")
        )

        flash(
            f"'{filename}' uploaded successfully to AWS S3!",
            "success"
        )

    except Exception as e:

        flash(
            f"Upload failed: {e}",
            "error"
        )

    return redirect(url_for("dashboard"))


# ============================================================
# DOWNLOAD
# ============================================================

@app.route("/download/<path:filename>")
@login_required
def download_file(filename):

    try:

        filename = secure_filename(
            os.path.basename(filename)
        )

        s3_key = get_user_file_key(filename)

        file_stream = BytesIO()

        s3.download_fileobj(
            AWS_BUCKET_NAME,
            s3_key,
            file_stream
        )

        file_stream.seek(0)

        return send_file(
            file_stream,
            as_attachment=True,
            download_name=filename
        )

    except Exception as e:

        flash(
            f"Download failed: {e}",
            "error"
        )

        return redirect(url_for("dashboard"))


# ============================================================
# DELETE
# ============================================================

@app.route("/delete/<path:filename>")
@login_required
def delete_file(filename):

    try:

        filename = secure_filename(
            os.path.basename(filename)
        )

        s3_key = get_user_file_key(filename)

        s3.delete_object(
            Bucket=AWS_BUCKET_NAME,
            Key=s3_key
        )

        record_backup_action(
            filename=filename,
            action="DELETE"
        )

        flash(
            f"'{filename}' deleted successfully.",
            "success"
        )

    except Exception as e:

        flash(
            f"Delete failed: {e}",
            "error"
        )

    return redirect(url_for("dashboard"))


# ============================================================
# VERSION HISTORY
# ============================================================

@app.route("/versions/<path:filename>")
@login_required
def file_versions(filename):

    versions = []

    try:

        filename = secure_filename(
            os.path.basename(filename)
        )

        s3_key = get_user_file_key(filename)

        response = s3.list_object_versions(
            Bucket=AWS_BUCKET_NAME,
            Prefix=s3_key
        )

        for version in response.get("Versions", []):

            if version["Key"] == s3_key:

                versions.append({
                    "version_id": version["VersionId"],
                    "last_modified": version["LastModified"],
                    "size": version["Size"],
                    "is_latest": version["IsLatest"],
                    "delete_marker": False
                })

        for marker in response.get("DeleteMarkers", []):

            if marker["Key"] == s3_key:

                versions.append({
                    "version_id": marker["VersionId"],
                    "last_modified": marker["LastModified"],
                    "size": 0,
                    "is_latest": marker["IsLatest"],
                    "delete_marker": True
                })

        versions.sort(
            key=lambda x: x["last_modified"],
            reverse=True
        )

    except Exception as e:

        flash(
            f"Could not retrieve versions: {e}",
            "error"
        )

    return render_template(
        "versions.html",
        filename=filename,
        versions=versions
    )


# ============================================================
# RECOVER
# ============================================================

@app.route(
    "/recover/<path:filename>/<version_id>",
    methods=["POST"]
)
@login_required
def recover_file(filename, version_id):

    try:

        filename = secure_filename(
            os.path.basename(filename)
        )

        s3_key = get_user_file_key(filename)

        response = s3.get_object(
            Bucket=AWS_BUCKET_NAME,
            Key=s3_key,
            VersionId=version_id
        )

        file_data = response["Body"].read()

        s3.put_object(
            Bucket=AWS_BUCKET_NAME,
            Key=s3_key,
            Body=file_data
        )

        record_backup_action(
            filename=filename,
            action="RECOVERY",
            version_id=version_id,
            file_size=len(file_data)
        )

        flash(
            f"'{filename}' has been successfully recovered!",
            "success"
        )

    except Exception as e:

        flash(
            f"Recovery failed: {e}",
            "error"
        )

    return redirect(
        url_for(
            "file_versions",
            filename=filename
        )
    )


# ============================================================
# BACKUP HISTORY
# ============================================================

@app.route("/history")
@login_required
def backup_history():

    connection = get_db()

    history = connection.execute(
        """
        SELECT *
        FROM backup_history
        WHERE user_id = ?
        ORDER BY timestamp DESC
        """,
        (session["user_id"],)
    ).fetchall()

    connection.close()

    return render_template(
        "history.html",
        history=history,
        username=session.get("username")
    )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    init_db()

    app.run(debug=True)