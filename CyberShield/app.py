"""
CyberShield — AI-Powered Cybersecurity Threat Detection Platform
Full-stack web application with JWT authentication and security modules.
"""

from functools import wraps
from io import BytesIO

from flask import (
    Flask,
    flash,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    jwt_required,
    set_access_cookies,
    unset_jwt_cookies,
    verify_jwt_in_request,
)
from flask_jwt_extended.exceptions import JWTExtendedException
from jwt.exceptions import PyJWTError

import config
import project_info
from database import (
    admin_stats,
    create_user,
    get_all_users,
    get_recent_scans,
    get_scan_by_id,
    get_threat_stats,
    get_user_by_id,
    get_user_by_username,
    get_user_history,
    init_db,
    save_ai_message,
    save_scan,
    verify_user,
)
from services.ai_assistant import ask_assistant
from services.hash_checker import check_hash
from services.log_analyzer import analyze_logs
from services.news_fetcher import fetch_security_news
from services.password_analyzer import analyze_password
from services.pdf_report import generate_scan_report
from services.url_detector import analyze_url
from services.vuln_scanner import scan_url

app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY
app.config["JWT_SECRET_KEY"] = config.JWT_SECRET_KEY
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_CSRF_PROTECT"] = False
app.config["JWT_ACCESS_COOKIE_NAME"] = "cybershield_token"

jwt = JWTManager(app)

with app.app_context():
    init_db()
    if not get_user_by_username(config.ADMIN_USERNAME):
        create_user(
            config.ADMIN_USERNAME,
            config.ADMIN_EMAIL,
            config.ADMIN_PASSWORD,
            role="admin",
        )


@app.context_processor
def inject_globals():
    return {
        "project": {
            "title": project_info.PROJECT_TITLE,
            "subtitle": project_info.PROJECT_SUBTITLE,
            "student_name": project_info.STUDENT_NAME,
            "college_name": project_info.COLLEGE_NAME,
            "academic_year": project_info.ACADEMIC_YEAR,
        }
    }


def login_required_page(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        try:
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            user = get_user_by_id(int(user_id))
            if not user:
                return redirect(url_for("login"))
            return view(user, *args, **kwargs)
        except (JWTExtendedException, PyJWTError):
            return redirect(url_for("login", next=request.path))

    return wrapped


def admin_required_page(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        try:
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            user = get_user_by_id(int(user_id))
            if not user or user["role"] != "admin":
                flash("Admin access required.", "error")
                return redirect(url_for("dashboard"))
            return view(user, *args, **kwargs)
        except (JWTExtendedException, PyJWTError):
            return redirect(url_for("login"))

    return wrapped


# ── Public pages ──

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = verify_user(username, password)
        if user:
            token = create_access_token(identity=str(user["id"]))
            response = make_response(redirect(request.args.get("next") or url_for("dashboard")))
            set_access_cookies(response, token)
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash(f"Welcome back, {user['username']}!", "success")
            return response
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if not username or not email or not password:
            flash("All fields are required.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        elif get_user_by_username(username):
            flash("Username already exists.", "error")
        else:
            create_user(username, email, password)
            flash("Account created! Please log in.", "success")
            return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/logout")
def logout():
    response = make_response(redirect(url_for("index")))
    unset_jwt_cookies(response)
    session.clear()
    flash("Logged out successfully.", "success")
    return response


# ── Dashboard & modules ──

@app.route("/dashboard")
@login_required_page
def dashboard(user):
    stats = get_threat_stats(user["id"])
    recent = get_recent_scans(limit=8, user_id=user["id"])
    news = fetch_security_news(limit=4)
    return render_template(
        "dashboard.html",
        user=user,
        stats=stats,
        recent=recent,
        news=news,
    )


@app.route("/modules/<module_name>")
@login_required_page
def module_page(user, module_name):
    valid = {
        "password", "url", "vuln", "hash", "logs", "ai", "news", "threat-intel"
    }
    if module_name not in valid:
        flash("Module not found.", "error")
        return redirect(url_for("dashboard"))
    return render_template(f"modules/{module_name}.html", user=user, module=module_name)


@app.route("/history")
@login_required_page
def history(user):
    scans = get_user_history(user["id"], limit=100)
    return render_template("history.html", user=user, scans=scans)


@app.route("/admin")
@admin_required_page
def admin_dashboard(user):
    stats = admin_stats()
    users = get_all_users()
    recent = get_recent_scans(limit=15)
    threat = get_threat_stats()
    return render_template(
        "admin/dashboard.html",
        user=user,
        stats=stats,
        users=users,
        recent=recent,
        threat=threat,
    )


# ── API endpoints (JWT protected) ──

@app.route("/api/scan/password", methods=["POST"])
@jwt_required()
def api_password_scan():
    user_id = int(get_jwt_identity())
    password = request.form.get("password", "")
    if not password and request.is_json:
        password = (request.get_json() or {}).get("password", "")
    result = analyze_password(password)
    scan_id = save_scan(user_id, "password", "Password analysis", result, result["risk_level"])
    result["scan_id"] = scan_id
    return jsonify(result)


@app.route("/api/scan/url", methods=["POST"])
@jwt_required()
def api_url_scan():
    user_id = int(get_jwt_identity())
    url = request.form.get("url", "") or (request.get_json() or {}).get("url", "")
    if not url:
        return jsonify({"error": "URL is required"}), 400
    result = analyze_url(url)
    scan_id = save_scan(user_id, "url", url[:100], result, result["risk_level"])
    result["scan_id"] = scan_id
    return jsonify(result)


@app.route("/api/scan/vuln", methods=["POST"])
@jwt_required()
def api_vuln_scan():
    user_id = int(get_jwt_identity())
    target = request.form.get("target", "") or (request.get_json() or {}).get("target", "")
    if not target:
        return jsonify({"error": "Target URL is required"}), 400
    result = scan_url(target)
    scan_id = save_scan(user_id, "vuln", target[:100], result, result["risk_level"])
    result["scan_id"] = scan_id
    return jsonify(result)


@app.route("/api/scan/hash", methods=["POST"])
@jwt_required()
def api_hash_scan():
    user_id = int(get_jwt_identity())
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    data = file.read()
    if len(data) > 10 * 1024 * 1024:
        return jsonify({"error": "File too large (max 10MB)"}), 400
    result = check_hash(data, file.filename or "upload")
    scan_id = save_scan(user_id, "hash", file.filename or "file", result, result["risk_level"])
    result["scan_id"] = scan_id
    return jsonify(result)


@app.route("/api/scan/logs", methods=["POST"])
@jwt_required()
def api_log_scan():
    user_id = int(get_jwt_identity())
    log_text = request.form.get("log_text", "") or (request.get_json() or {}).get("log_text", "")
    if "file" in request.files and request.files["file"].filename:
        log_text = request.files["file"].read().decode("utf-8", errors="replace")
    result = analyze_logs(log_text)
    scan_id = save_scan(user_id, "logs", f"{len(log_text.splitlines())} lines", result, result["risk_level"])
    result["scan_id"] = scan_id
    return jsonify(result)


@app.route("/api/ai/ask", methods=["POST"])
@jwt_required()
def api_ai_ask():
    user_id = int(get_jwt_identity())
    question = request.form.get("question", "") or (request.get_json() or {}).get("question", "")
    response = ask_assistant(question)
    save_ai_message(user_id, question, response["answer"])
    return jsonify(response)


@app.route("/api/news")
@jwt_required()
def api_news():
    return jsonify(fetch_security_news(limit=15))


@app.route("/api/threat-stats")
@jwt_required()
def api_threat_stats():
    user_id = int(get_jwt_identity())
    user = get_user_by_id(user_id)
    uid = None if user and user["role"] == "admin" and request.args.get("global") else user_id
    return jsonify(get_threat_stats(uid))


@app.route("/api/report/<int:scan_id>")
@jwt_required()
def api_report(scan_id):
    user_id = int(get_jwt_identity())
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    scan = get_scan_by_id(scan_id, user_id if user["role"] != "admin" else None)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    pdf_bytes = generate_scan_report(
        {"module": scan["module"], "input_summary": scan["input_summary"], "result": scan["result"]},
        user["username"],
    )
    return send_file(
        BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"cybershield_report_{scan_id}.pdf",
    )


if __name__ == "__main__":
    import os
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    print("\n  CyberShield — Threat Detection Platform")
    print("  =========================================")
    print(f"  Website:  http://{config.HOST}:{config.PORT}")
    print(f"  Admin:    {config.ADMIN_USERNAME} / {config.ADMIN_PASSWORD}\n")
    app.run(host=config.HOST, port=config.PORT, debug=debug)
