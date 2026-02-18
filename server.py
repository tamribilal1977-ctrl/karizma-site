import hashlib
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "karizma.db")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
NAME_RE = re.compile(r"^[\w\s\u0600-\u06FF'.-]{3,80}$")

PASSWORD_MIN_LENGTH = 10
PASSWORD_ITERATIONS = 260000
SESSION_TTL_HOURS = 12
MAX_JSON_BODY_BYTES = 16 * 1024
MAX_URI_LENGTH = 2048
MAX_HEADER_VALUE_LENGTH = 2048

RATE_BUCKET_LOCK = threading.Lock()
RATE_BUCKETS = {}
FIREWALL_LOCK = threading.Lock()
FIREWALL_STATE = {}

LOGIN_IP_LIMIT = (10, 60)
LOGIN_EMAIL_LIMIT = (6, 300)
REGISTER_IP_LIMIT = (8, 60)

FIREWALL_STRIKE_WINDOW_SECONDS = 180
FIREWALL_MAX_STRIKES = 6
FIREWALL_BLOCK_SECONDS = 900
SECURITY_LOG_PATH = os.path.join(BASE_DIR, "security.log")

ATTACK_PATTERNS = [
    re.compile(r"(?i)(?:union\s+select|information_schema|benchmark\(|sleep\()"),
    re.compile(r"(?i)(?:<script|%3cscript|javascript:)"),
    re.compile(r"(?i)(?:\.\./|%2e%2e%2f|/etc/passwd|\\windows\\system32)"),
    re.compile(r"(?i)(?:\b(or|and)\b\s+\d=\d)"),
]

SCANNER_UA_PATTERNS = [
    re.compile(r"(?i)(sqlmap|nikto|nmap|acunetix|masscan|wpscan|burpsuite|owasp)"),
]


def now_utc():
    return datetime.now(timezone.utc)


def utc_iso(dt):
    return dt.isoformat()


def parse_utc(iso_text):
    return datetime.fromisoformat(iso_text)


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def ensure_column(conn, table_name, column_name, column_sql):
    columns = {
        row["name"]
        for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    }
    if column_name not in columns:
        conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_sql}")


def init_db():
    conn = get_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                password_iter INTEGER NOT NULL DEFAULT 120000,
                created_at TEXT NOT NULL
            )
            """
        )
        ensure_column(conn, "users", "password_iter", "password_iter INTEGER NOT NULL DEFAULT 120000")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                ip TEXT,
                user_agent TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)")
        conn.commit()
    finally:
        conn.close()


def hash_password(password, salt_hex, iterations):
    salt = bytes.fromhex(salt_hex)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return digest.hex()


def validate_password_strength(password):
    if len(password) < PASSWORD_MIN_LENGTH:
        return "كلمة المرور لازم تكون 10 أحرف على الأقل."
    if not re.search(r"[A-Za-z\u0600-\u06FF]", password):
        return "كلمة المرور لازم تحتوي على حرف واحد على الأقل."
    if not re.search(r"\d", password):
        return "كلمة المرور لازم تحتوي على رقم واحد على الأقل."
    return None


def consume_rate_limit(bucket_name, key, limit, window_seconds):
    now = time.time()
    bucket_key = f"{bucket_name}:{key}"
    with RATE_BUCKET_LOCK:
        timestamps = RATE_BUCKETS.get(bucket_key, [])
        timestamps = [t for t in timestamps if (now - t) <= window_seconds]
        if len(timestamps) >= limit:
            retry_after = max(1, int(window_seconds - (now - timestamps[0])))
            RATE_BUCKETS[bucket_key] = timestamps
            return False, retry_after
        timestamps.append(now)
        RATE_BUCKETS[bucket_key] = timestamps
    return True, 0


def clear_rate_limit(bucket_name, key):
    bucket_key = f"{bucket_name}:{key}"
    with RATE_BUCKET_LOCK:
        RATE_BUCKETS.pop(bucket_key, None)


def security_log(ip, reason, path="", method=""):
    timestamp = now_utc().strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"{timestamp} ip={ip} method={method} path={path} reason={reason}\n"
    try:
        with open(SECURITY_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        # Logging must not break request handling.
        pass


def firewall_is_blocked(ip):
    now = time.time()
    with FIREWALL_LOCK:
        state = FIREWALL_STATE.get(ip)
        if not state:
            return False, 0
        blocked_until = state.get("blocked_until", 0)
        if blocked_until > now:
            return True, int(blocked_until - now)
        if blocked_until:
            state["blocked_until"] = 0
    return False, 0


def firewall_register_strike(ip, reason, path="", method=""):
    now = time.time()
    with FIREWALL_LOCK:
        state = FIREWALL_STATE.setdefault(ip, {"strikes": [], "blocked_until": 0})
        strikes = [t for t in state["strikes"] if (now - t) <= FIREWALL_STRIKE_WINDOW_SECONDS]
        strikes.append(now)
        state["strikes"] = strikes
        blocked = False
        retry_after = 0
        if len(strikes) >= FIREWALL_MAX_STRIKES:
            state["blocked_until"] = now + FIREWALL_BLOCK_SECONDS
            blocked = True
            retry_after = FIREWALL_BLOCK_SECONDS
    security_log(ip, reason, path, method)
    return blocked, retry_after


def looks_malicious(text):
    if not text:
        return False
    for pattern in ATTACK_PATTERNS:
        if pattern.search(text):
            return True
    return False


class AppHandler(SimpleHTTPRequestHandler):
    server_version = "KarizmaHTTP/1.0"

    def version_string(self):
        return self.server_version

    def list_directory(self, path):
        self.send_error(403, "Directory listing is disabled")
        return None

    def _json_response(self, status_code, payload, extra_headers=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _get_ip(self):
        return self.client_address[0] if self.client_address else "0.0.0.0"

    def _firewall_deny(self, status_code, reason, retry_after=0):
        ip = self._get_ip()
        headers = {}
        if retry_after > 0:
            headers["Retry-After"] = str(retry_after)
        return self._json_response(status_code, {"error": reason}, headers)

    def _firewall_check_request(self, method):
        ip = self._get_ip()
        blocked, retry_after = firewall_is_blocked(ip)
        if blocked:
            security_log(ip, "blocked_ip", self.path, method)
            self._firewall_deny(429, "IP blocked temporarily by firewall.", retry_after)
            return False

        if method not in {"GET", "POST"}:
            is_blocked, wait_for = firewall_register_strike(ip, "invalid_method", self.path, method)
            self._firewall_deny(429 if is_blocked else 405, "Method not allowed.", wait_for)
            return False

        raw_path = self.path or "/"
        if len(raw_path) > MAX_URI_LENGTH:
            is_blocked, wait_for = firewall_register_strike(ip, "uri_too_long", raw_path, method)
            self._firewall_deny(429 if is_blocked else 414, "Request URI too long.", wait_for)
            return False

        if looks_malicious(raw_path):
            is_blocked, wait_for = firewall_register_strike(ip, "malicious_uri", raw_path, method)
            self._firewall_deny(429 if is_blocked else 403, "Request blocked by firewall.", wait_for)
            return False

        parsed = urlparse(raw_path)
        if not parsed.path.startswith("/") or ".." in parsed.path:
            is_blocked, wait_for = firewall_register_strike(ip, "path_traversal", raw_path, method)
            self._firewall_deny(429 if is_blocked else 403, "Request blocked by firewall.", wait_for)
            return False

        user_agent = self.headers.get("User-Agent", "")
        for pattern in SCANNER_UA_PATTERNS:
            if pattern.search(user_agent):
                is_blocked, wait_for = firewall_register_strike(ip, "scanner_user_agent", raw_path, method)
                self._firewall_deny(429 if is_blocked else 403, "Request blocked by firewall.", wait_for)
                return False

        for key, value in self.headers.items():
            if len(value) > MAX_HEADER_VALUE_LENGTH:
                is_blocked, wait_for = firewall_register_strike(ip, f"header_too_long:{key}", raw_path, method)
                self._firewall_deny(429 if is_blocked else 400, "Bad request headers.", wait_for)
                return False
            if looks_malicious(value):
                is_blocked, wait_for = firewall_register_strike(ip, f"malicious_header:{key}", raw_path, method)
                self._firewall_deny(429 if is_blocked else 403, "Request blocked by firewall.", wait_for)
                return False

        return True

    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None, "Invalid content length"
        if length <= 0:
            return None, "Request body is required"
        if length > MAX_JSON_BODY_BYTES:
            return None, "Request body is too large"
        body = self.rfile.read(length)
        text_body = body.decode("utf-8", errors="ignore")
        if looks_malicious(text_body):
            ip = self._get_ip()
            firewall_register_strike(ip, "malicious_body", self.path, "POST")
            return None, "Request blocked by firewall"
        return body, None

    def _validate_same_origin(self):
        # Mitigates CSRF by enforcing same-origin requests for state-changing endpoints.
        origin = self.headers.get("Origin")
        host = self.headers.get("Host")
        if origin and host:
            parsed = urlparse(origin)
            if parsed.netloc != host:
                return False
        return True

    def _validate_json_request(self):
        if not self._validate_same_origin():
            return False, (403, {"error": "Invalid origin"})
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            return False, (415, {"error": "Content-Type must be application/json"})
        if self.headers.get("X-Requested-With") != "XMLHttpRequest":
            return False, (400, {"error": "Missing required request header"})
        return True, None

    def _parse_json(self):
        body, error = self._read_body()
        if error:
            return None, error
        try:
            return json.loads(body.decode("utf-8")), None
        except json.JSONDecodeError:
            return None, "Invalid JSON payload"

    def _parse_cookies(self):
        cookie_header = self.headers.get("Cookie", "")
        jar = SimpleCookie()
        if cookie_header:
            jar.load(cookie_header)
        return jar

    def _session_cookie(self, token):
        secure_cookie = os.environ.get("COOKIE_SECURE", "0") == "1"
        parts = [
            f"sid={token}",
            "HttpOnly",
            "Path=/",
            "SameSite=Strict",
            f"Max-Age={SESSION_TTL_HOURS * 3600}",
        ]
        if secure_cookie:
            parts.append("Secure")
        return "; ".join(parts)

    def _clear_session_cookie(self):
        secure_cookie = os.environ.get("COOKIE_SECURE", "0") == "1"
        parts = ["sid=; HttpOnly", "Path=/", "SameSite=Strict", "Max-Age=0"]
        if secure_cookie:
            parts.append("Secure")
        return "; ".join(parts)

    def _create_session(self, user_id):
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        created_at = now_utc()
        expires_at = created_at + timedelta(hours=SESSION_TTL_HOURS)

        conn = get_connection()
        try:
            conn.execute(
                """
                INSERT INTO sessions (user_id, token_hash, created_at, expires_at, ip, user_agent)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    token_hash,
                    utc_iso(created_at),
                    utc_iso(expires_at),
                    self._get_ip(),
                    self.headers.get("User-Agent", "")[:255],
                ),
            )
            conn.commit()
        finally:
            conn.close()
        return raw_token

    def _cleanup_expired_sessions(self):
        conn = get_connection()
        try:
            conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (utc_iso(now_utc()),))
            conn.commit()
        finally:
            conn.close()

    def _get_current_user(self):
        jar = self._parse_cookies()
        sid = jar.get("sid")
        if sid is None:
            return None
        token_hash = hashlib.sha256(sid.value.encode("utf-8")).hexdigest()
        conn = get_connection()
        try:
            row = conn.execute(
                """
                SELECT u.id, u.name, u.email, s.id AS session_id, s.expires_at
                FROM sessions s
                JOIN users u ON u.id = s.user_id
                WHERE s.token_hash = ?
                """,
                (token_hash,),
            ).fetchone()
            if row is None:
                return None
            if parse_utc(row["expires_at"]) <= now_utc():
                conn.execute("DELETE FROM sessions WHERE id = ?", (row["session_id"],))
                conn.commit()
                return None
            return {"id": row["id"], "name": row["name"], "email": row["email"], "session_id": row["session_id"]}
        finally:
            conn.close()

    def _require_auth_for_page(self, path):
        protected_pages = {"/course.html"}
        if path not in protected_pages:
            return False
        return self._get_current_user() is None

    def do_GET(self):
        if not self._firewall_check_request("GET"):
            return
        self._cleanup_expired_sessions()
        path = urlparse(self.path).path

        if path == "/api/me":
            user = self._get_current_user()
            if user is None:
                return self._json_response(401, {"authenticated": False})
            return self._json_response(
                200,
                {
                    "authenticated": True,
                    "user": {"id": user["id"], "name": user["name"], "email": user["email"]},
                },
            )

        if self._require_auth_for_page(path):
            self.send_response(302)
            self.send_header("Location", "/login.html")
            self.end_headers()
            return

        super().do_GET()

    def do_POST(self):
        if not self._firewall_check_request("POST"):
            return
        self._cleanup_expired_sessions()
        path = urlparse(self.path).path

        valid_json, reason = self._validate_json_request()
        if not valid_json:
            status_code, payload = reason
            return self._json_response(status_code, payload)

        if path == "/api/register":
            return self.handle_register()
        if path == "/api/login":
            return self.handle_login()
        if path == "/api/logout":
            return self.handle_logout()
        return self._json_response(404, {"error": "Not found"})

    def do_PUT(self):
        self._firewall_check_request("PUT")

    def do_DELETE(self):
        self._firewall_check_request("DELETE")

    def do_PATCH(self):
        self._firewall_check_request("PATCH")

    def do_OPTIONS(self):
        self._firewall_check_request("OPTIONS")

    def do_HEAD(self):
        self._firewall_check_request("HEAD")

    def handle_register(self):
        allowed, retry_after = consume_rate_limit(
            "register-ip", self._get_ip(), REGISTER_IP_LIMIT[0], REGISTER_IP_LIMIT[1]
        )
        if not allowed:
            return self._json_response(
                429,
                {"error": "محاولات كثيرة. حاول مرة أخرى بعد قليل."},
                {"Retry-After": str(retry_after)},
            )

        data, error = self._parse_json()
        if error:
            return self._json_response(400, {"error": error})

        name = (data.get("name") or "").strip()
        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""

        if not NAME_RE.match(name):
            return self._json_response(400, {"error": "الاسم غير صالح."})
        if not EMAIL_RE.match(email):
            return self._json_response(400, {"error": "الايميل غير صالح."})

        password_error = validate_password_strength(password)
        if password_error:
            return self._json_response(400, {"error": password_error})

        salt = secrets.token_hex(16)
        password_hash = hash_password(password, salt, PASSWORD_ITERATIONS)
        created_at = utc_iso(now_utc())

        conn = get_connection()
        try:
            conn.execute(
                """
                INSERT INTO users (name, email, salt, password_hash, password_iter, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (name, email, salt, password_hash, PASSWORD_ITERATIONS, created_at),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return self._json_response(409, {"error": "هذا الايميل مسجل من قبل."})
        finally:
            conn.close()

        return self._json_response(201, {"ok": True, "message": "تم انشاء الحساب."})

    def handle_login(self):
        data, error = self._parse_json()
        if error:
            return self._json_response(400, {"error": error})

        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""

        if not EMAIL_RE.match(email):
            return self._json_response(400, {"error": "الايميل غير صالح."})
        if len(password) < 6:
            return self._json_response(400, {"error": "كلمة المرور قصيرة."})

        ip_key = self._get_ip()
        allowed_ip, retry_ip = consume_rate_limit("login-ip", ip_key, LOGIN_IP_LIMIT[0], LOGIN_IP_LIMIT[1])
        if not allowed_ip:
            return self._json_response(
                429,
                {"error": "محاولات كثيرة. حاول مرة أخرى بعد قليل."},
                {"Retry-After": str(retry_ip)},
            )

        allowed_email, retry_email = consume_rate_limit(
            "login-email", email, LOGIN_EMAIL_LIMIT[0], LOGIN_EMAIL_LIMIT[1]
        )
        if not allowed_email:
            return self._json_response(
                429,
                {"error": "تم قفل الحساب مؤقتا بعد محاولات كثيرة. حاول لاحقا."},
                {"Retry-After": str(retry_email)},
            )

        conn = get_connection()
        try:
            row = conn.execute(
                """
                SELECT id, name, email, salt, password_hash, password_iter
                FROM users
                WHERE email = ?
                """,
                (email,),
            ).fetchone()
        finally:
            conn.close()

        if row is None:
            return self._json_response(401, {"error": "بيانات الدخول غير صحيحة."})

        expected_hash = hash_password(password, row["salt"], int(row["password_iter"]))
        if not secrets.compare_digest(expected_hash, row["password_hash"]):
            return self._json_response(401, {"error": "بيانات الدخول غير صحيحة."})

        session_token = self._create_session(row["id"])
        clear_rate_limit("login-email", email)
        clear_rate_limit("login-ip", ip_key)
        return self._json_response(
            200,
            {"ok": True, "user": {"id": row["id"], "name": row["name"], "email": row["email"]}},
            {"Set-Cookie": self._session_cookie(session_token)},
        )

    def handle_logout(self):
        user = self._get_current_user()
        if user:
            conn = get_connection()
            try:
                conn.execute("DELETE FROM sessions WHERE id = ?", (user["session_id"],))
                conn.commit()
            finally:
                conn.close()
        return self._json_response(200, {"ok": True}, {"Set-Cookie": self._clear_session_cookie()})

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self' https://fonts.googleapis.com; "
                "font-src 'self' https://fonts.gstatic.com; "
                "img-src 'self' data:; "
                "connect-src 'self'; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self'"
            ),
        )
        super().end_headers()


def run():
    init_db()
    port = int(os.environ.get("PORT", "8000"))
    server = HTTPServer(("127.0.0.1", port), AppHandler)
    print(f"Server running on http://127.0.0.1:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run()
