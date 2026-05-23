from flask import Flask, request, jsonify, render_template, Response
from scanner import PackageScanner
import json
import os
from werkzeug.security import check_password_hash
from dotenv import load_dotenv
from functools import wraps
from database import get_connection

load_dotenv()

app = Flask(__name__)
scanner = PackageScanner()

def check_auth(username, password):
    expected_user = os.environ.get("ADMIN_USERNAME")
    expected_hash = os.environ.get("ADMIN_PASSWORD_HASH")
    if not expected_user or not expected_hash:
        return False
    return username == expected_user and check_password_hash(expected_hash, password)

def authenticate():
    return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/admin")
@requires_auth
def admin():
    return render_template("admin.html")

@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json()
    if not data or "packageJson" not in data:
        return jsonify({"error": "Missing packageJson field"}), 400
    try:
        pkg_json = json.loads(data["packageJson"])
    except json.JSONDecodeError as e:
        return jsonify({"error": f"Invalid JSON: {str(e)}"}), 400

    results = scanner.scan(pkg_json)
    return jsonify(results)

@app.route("/api/stats", methods=["GET"])
def stats():
    return jsonify(scanner.get_stats())

@app.route("/api/tools", methods=["GET"])
def get_tools():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM tools").fetchall()
    conn.close()
    tools = [dict(row) for row in rows]
    return jsonify(tools)

@app.route("/api/tools", methods=["POST"])
@requires_auth
def add_tool():
    data = request.get_json()
    required = ["type", "cls", "name", "desc", "url"]
    if not data or not all(k in data for k in required):
        return jsonify({"error": "Missing fields"}), 400
    
    conn = get_connection()
    conn.execute(
        "INSERT INTO tools (type, cls, name, desc, url) VALUES (?, ?, ?, ?, ?)",
        (data["type"], data["cls"], data["name"], data["desc"], data["url"])
    )
    conn.commit()
    conn.close()
    return jsonify({"success": True})

@app.route("/api/tools/<int:tool_id>", methods=["DELETE"])
@requires_auth
def delete_tool(tool_id):
    conn = get_connection()
    conn.execute("DELETE FROM tools WHERE id = ?", (tool_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

if __name__ == "__main__":
    app.run(debug=True, port=5000)
