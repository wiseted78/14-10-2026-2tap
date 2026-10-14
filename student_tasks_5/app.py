from functools import wraps
from pathlib import Path
import argparse
import os
import secrets
import sqlite3

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
app = Flask(__name__)
app.config.update(
    DATABASE=str(BASE_DIR / "site.db"),
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_NAME="student_tasks_" + BASE_DIR.name,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                done INTEGER NOT NULL DEFAULT 0 CHECK (done IN (0, 1))
            );
        """)
        db.commit()


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


@app.context_processor
def template_helpers():
    return {"csrf_token": csrf_token}


@app.before_request
def load_user_and_check_form():
    g.user = None
    if session.get("user_id"):
        g.user = get_db().execute(
            "SELECT id, username FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
        if g.user is None:
            session.clear()
    if request.method == "POST":
        expected = session.get("csrf_token", "")
        supplied = request.form.get("csrf_token", "")
        if not expected or not secrets.compare_digest(expected.encode(), supplied.encode()):
            abort(400)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/")
def index():
    return redirect(url_for("tasks") if g.user else url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("tasks"))
    username = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not 3 <= len(username) <= 30:
            flash("Пайдаланушы аты 3–30 таңбадан тұруы керек.", "error")
        elif not 6 <= len(password) <= 128:
            flash("Құпиясөз 6–128 таңбадан тұруы керек.", "error")
        else:
            db = get_db()
            try:
                cursor = db.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                examples = [
                    ("HTML құрылымын қайталау", "Тақырып, абзац және сілтеме тегтерін қарап шығу.", 0),
                    ("CSS бойынша жаттығу", "Карточканың түсін және ішкі аралығын реттеу.", 0),
                    ("Сабаққа дайындалу", "Дәптер мен оқу материалдарын дайындау.", 1),
                ]
                db.executemany(
                    "INSERT INTO tasks (user_id, title, description, done) VALUES (?, ?, ?, ?)",
                    [(cursor.lastrowid, title, description, done) for title, description, done in examples],
                )
                db.commit()
            except sqlite3.IntegrityError:
                db.rollback()
                flash("Бұл пайдаланушы аты бос емес. Басқа ат таңдаңыз.", "error")
            else:
                flash("Тіркелу сәтті аяқталды. Енді жүйеге кіріңіз.", "success")
                return redirect(url_for("login"))
    return render_template("register.html", username=username)


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("tasks"))
    username = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            flash("Қош келдіңіз! Бүгінгі жоспарыңызды реттейік.", "success")
            return redirect(url_for("tasks"))
        flash("Пайдаланушы аты немесе құпиясөз қате.", "error")
    return render_template("login.html", username=username)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/tasks")
@login_required
def tasks():
    items = get_db().execute(
        "SELECT * FROM tasks WHERE user_id = ? ORDER BY done, id DESC", (g.user["id"],)
    ).fetchall()
    completed = sum(item["done"] for item in items)
    return render_template("tasks.html", tasks=items, total=len(items), completed=completed)


@app.route("/tasks/new", methods=["GET", "POST"])
@login_required
def new_task():
    title, description = "", ""
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        if not 1 <= len(title) <= 100:
            flash("Тапсырма атауы 1–100 таңбадан тұруы керек.", "error")
        elif len(description) > 500:
            flash("Сипаттама 500 таңбадан аспауы керек.", "error")
        else:
            db = get_db()
            db.execute(
                "INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)",
                (g.user["id"], title, description),
            )
            db.commit()
            flash("Жаңа тапсырма сақталды.", "success")
            return redirect(url_for("tasks"))
    return render_template("new_task.html", title=title, description=description)


def owned_task(task_id):
    task = get_db().execute(
        "SELECT * FROM tasks WHERE id = ? AND user_id = ?", (task_id, g.user["id"])
    ).fetchone()
    if task is None:
        abort(404)
    return task


@app.route("/tasks/<int:task_id>/toggle", methods=["POST"])
@login_required
def toggle_task(task_id):
    task = owned_task(task_id)
    db = get_db()
    db.execute("UPDATE tasks SET done = ? WHERE id = ? AND user_id = ?",
               (1 - task["done"], task_id, g.user["id"]))
    db.commit()
    return redirect(url_for("tasks"))


@app.route("/tasks/<int:task_id>/delete", methods=["POST"])
@login_required
def delete_task(task_id):
    owned_task(task_id)
    db = get_db()
    db.execute("DELETE FROM tasks WHERE id = ? AND user_id = ?", (task_id, g.user["id"]))
    db.commit()
    flash("Тапсырма өшірілді.", "success")
    return redirect(url_for("tasks"))


@app.route("/guide")
@login_required
def guide():
    return render_template("guide.html")


@app.errorhandler(400)
def bad_request(error):
    return render_template("error.html", code=400, message="Сұрау қабылданбады. Бетті жаңартып, қайталап көріңіз."), 400


@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", code=404, message="Бұл бет табылмады. Мәзір арқылы қажетті бетке өтіңіз."), 404


init_db()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Студенттің тапсырмалар тізімі")
    parser.add_argument("--port", type=int, default=5000, help="Сервер порты")
    args = parser.parse_args()
    app.run(host="127.0.0.1", port=args.port, debug=False)
