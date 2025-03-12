# ```python
#!/usr/bin/env python3
"""
Single-file Bookmark Manager with SQLite
"""

import os
import sys
import time
import sqlite3
import hashlib
import random
import string
import urllib.request
import urllib.parse
import tarfile
import http.server
import socketserver
import html
import json
import logging
import threading
import datetime
import subprocess
import base64
import ssl
from http import cookies
from urllib.parse import parse_qs, urlparse

# Configuration
DB_FILE = "bookmarks.db"
HOST = "localhost"
PORT = 8000
DOWNLOAD_FOLDER = "downloads"
SHARE_SECRET_LENGTH = 12

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize database
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )
    ''')
    
    # Create bookmarks table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS bookmarks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        url TEXT NOT NULL,
        category TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        share_id TEXT UNIQUE,
        visit_count INTEGER DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Create sessions table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')

    conn.commit()
    conn.close()

# Create downloads directory if it doesn't exist
if not os.path.exists(DOWNLOAD_FOLDER):
    os.makedirs(DOWNLOAD_FOLDER)

# User management functions
def hash_password(password):
    """Hash a password with SHA-256 and a random salt"""
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt.hex() + ':' + key.hex()

def verify_password(stored_hash, provided_password):
    """Verify a password against its hash"""
    salt_hex, key_hex = stored_hash.split(':')
    salt = bytes.fromhex(salt_hex)
    stored_key = bytes.fromhex(key_hex)
    new_key = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
    return new_key == stored_key

def create_user(username, password):
    """Create a new user with the given username and password"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    try:
        password_hash = hash_password(password)
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", 
                      (username, password_hash))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        # Username already exists
        return False
    finally:
        conn.close()

def authenticate_user(username, password):
    """Authenticate a user with username and password"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    
    if result is None:
        return None
    
    user_id, stored_hash = result
    if verify_password(stored_hash, password):
        return user_id
    
    return None

def create_session(user_id):
    """Create a new session for a user"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    session_id = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    expires_at = datetime.datetime.now() + datetime.timedelta(days=1)
    
    cursor.execute("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)",
                  (session_id, user_id, expires_at))
    conn.commit()
    conn.close()
    
    return session_id

def validate_session(session_id):
    """Validate a session and return the user_id if valid"""
    if not session_id:
        return None
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT user_id, expires_at FROM sessions WHERE id = ?", (session_id,))
    result = cursor.fetchone()
    
    if result is None:
        conn.close()
        return None
    
    user_id, expires_at = result
    
    # Check if session is expired
    if datetime.datetime.fromisoformat(expires_at) < datetime.datetime.now():
        cursor.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        conn.commit()
        conn.close()
        return None
    
    conn.close()
    return user_id

def get_username_by_id(user_id):
    """Get a username by user ID"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    result = cursor.fetchone()
    conn.close()
    
    if result is None:
        return None
    
    return result[0]

# Bookmark management functions
def add_bookmark(user_id, title, url, category=None):
    """Add a new bookmark for a user"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute(
        "INSERT INTO bookmarks (user_id, title, url, category) VALUES (?, ?, ?, ?)",
        (user_id, title, url, category)
    )
    conn.commit()
    bookmark_id = cursor.lastrowid
    conn.close()
    
    return bookmark_id

def get_user_bookmarks(user_id):
    """Get all bookmarks for a user"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT id, title, url, category, share_id, visit_count FROM bookmarks WHERE user_id = ? ORDER BY category, title",
        (user_id,)
    )
    bookmarks = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return bookmarks

def get_bookmark_by_id(bookmark_id, user_id=None):
    """Get a bookmark by ID, optionally checking ownership"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    if user_id:
        cursor.execute(
            "SELECT id, title, url, category, share_id, visit_count FROM bookmarks WHERE id = ? AND user_id = ?",
            (bookmark_id, user_id)
        )
    else:
        cursor.execute(
            "SELECT id, title, url, category, share_id, user_id, visit_count FROM bookmarks WHERE id = ?",
            (bookmark_id,)
        )
    
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return dict(result)
    return None

def get_bookmark_by_share_id(share_id):
    """Get a bookmark by its share ID"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT id, title, url, category, user_id, visit_count FROM bookmarks WHERE share_id = ?",
        (share_id,)
    )
    
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return dict(result)
    return None

def update_bookmark(bookmark_id, user_id, title=None, url=None, category=None):
    """Update a bookmark"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # First check if bookmark exists and belongs to user
    cursor.execute("SELECT id FROM bookmarks WHERE id = ? AND user_id = ?", (bookmark_id, user_id))
    if not cursor.fetchone():
        conn.close()
        return False
    
    # Update the fields that are provided
    updates = []
    params = []
    
    if title is not None:
        updates.append("title = ?")
        params.append(title)
    
    if url is not None:
        updates.append("url = ?")
        params.append(url)
    
    if category is not None:
        updates.append("category = ?")
        params.append(category)
    
    if not updates:
        conn.close()
        return True  # Nothing to update
    
    query = f"UPDATE bookmarks SET {', '.join(updates)} WHERE id = ? AND user_id = ?"
    params.extend([bookmark_id, user_id])
    
    cursor.execute(query, params)
    conn.commit()
    conn.close()
    
    return True

def delete_bookmark(bookmark_id, user_id):
    """Delete a bookmark"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM bookmarks WHERE id = ? AND user_id = ?", (bookmark_id, user_id))
    success = cursor.rowcount > 0
    conn.commit()
    conn.close()
    
    return success

def generate_share_id(bookmark_id, user_id):
    """Generate a unique share ID for a bookmark"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # First check if bookmark exists and belongs to user
    cursor.execute("SELECT share_id FROM bookmarks WHERE id = ? AND user_id = ?", (bookmark_id, user_id))
    result = cursor.fetchone()
    
    if not result:
        conn.close()
        return None
    
    # If share_id already exists, return it
    if result[0]:
        conn.close()
        return result[0]
    
    # Generate a new share_id
    share_id = ''.join(random.choices(string.ascii_letters + string.digits, k=SHARE_SECRET_LENGTH))
    
    cursor.execute("UPDATE bookmarks SET share_id = ? WHERE id = ?", (share_id, bookmark_id))
    conn.commit()
    conn.close()
    
    return share_id

def increment_visit_count(bookmark_id):
    """Increment the visit count for a bookmark"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("UPDATE bookmarks SET visit_count = visit_count + 1 WHERE id = ?", (bookmark_id,))
    conn.commit()
    conn.close()

# Bookmark download functions
def download_page(url, save_path):
    """Download a web page and save it to the given path"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as response, open(save_path, 'wb') as out_file:
            data = response.read()
            out_file.write(data)
        return True
    except Exception as e:
        logger.error(f"Error downloading {url}: {e}")
        return False

def create_bookmark_archive(user_id):
    """Create an archive of all bookmarks for a user"""
    username = get_username_by_id(user_id)
    if not username:
        return None
    
    # Create a temporary directory for this user
    user_temp_dir = os.path.join(DOWNLOAD_FOLDER, f"temp_{username}")
    if not os.path.exists(user_temp_dir):
        os.makedirs(user_temp_dir)
    
    # Get all bookmarks for this user
    bookmarks = get_user_bookmarks(user_id)
    
    # Download each bookmark's page
    for bookmark in bookmarks:
        # Create a safe filename from the bookmark title
        safe_title = "".join([c if c.isalnum() else "_" for c in bookmark["title"]])
        filename = f"{safe_title}_{bookmark['id']}.html"
        file_path = os.path.join(user_temp_dir, filename)
        
        # Download the page
        success = download_page(bookmark["url"], file_path)
        if not success:
            # Create a placeholder file for failed downloads
            with open(file_path, 'w') as f:
                f.write(f"<!DOCTYPE html><html><body><h1>Failed to download {bookmark['title']}</h1><p>URL: {bookmark['url']}</p></body></html>")
    
    # Create a tar file
    timestamp = datetime.datetime.now().strftime("%Y%m%d")
    tar_filename = f"{username}_{timestamp}.tar"
    tar_path = os.path.join(DOWNLOAD_FOLDER, tar_filename)
    
    with tarfile.open(tar_path, "w") as tar:
        for root, _, files in os.walk(user_temp_dir):
            for file in files:
                file_path = os.path.join(root, file)
                tar.add(file_path, arcname=os.path.basename(file_path))
    
    # Clean up the temporary directory
    for file in os.listdir(user_temp_dir):
        os.remove(os.path.join(user_temp_dir, file))
    os.rmdir(user_temp_dir)
    
    return tar_path

def send_archive_to_user(archive_path):
    """Send the archive to the user using the external send program"""
    try:
        # Call the external send program
        subprocess.run(["/usr/bin/send", archive_path], check=True)
        logger.info(f"Successfully sent archive: {archive_path}")
        return True
    except subprocess.SubprocessError as e:
        logger.error(f"Failed to send archive {archive_path}: {e}")
        return False
    except FileNotFoundError:
        logger.error(f"Send program not found at /usr/bin/send")
        return False

# Daily task to create and send archives for all users
def daily_archive_task():
    """Task to create and send archives for all users"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT id FROM users")
    user_ids = [row[0] for row in cursor.fetchall()]
    conn.close()
    
    for user_id in user_ids:
        archive_path = create_bookmark_archive(user_id)
        if archive_path:
            send_archive_to_user(archive_path)

# Scheduler for daily tasks
def start_scheduler():
    """Start the scheduler for daily tasks"""
    def scheduler_thread():
        while True:
            now = datetime.datetime.now()
            # Run at 2 AM every day
            target_time = now.replace(hour=2, minute=0, second=0, microsecond=0)
            if now > target_time:
                target_time += datetime.timedelta(days=1)
            
            # Sleep until target time
            sleep_seconds = (target_time - now).total_seconds()
            time.sleep(sleep_seconds)
            
            # Run the daily archive task
            try:
                daily_archive_task()
            except Exception as e:
                logger.error(f"Error in daily archive task: {e}")
            
            # Sleep a bit to avoid running multiple times
            time.sleep(60)
    
    thread = threading.Thread(target=scheduler_thread, daemon=True)
    thread.start()

# HTML templates
def render_template(title, content, user_id=None):
    """Render an HTML template with the given title and content"""
    username = get_username_by_id(user_id) if user_id else None
    
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - Bookmark Manager</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        .navbar {{
            background-color: #f8f9fa;
            padding: 10px 0;
            margin-bottom: 20px;
            border-bottom: 1px solid #ddd;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .navbar a {{
            text-decoration: none;
            color: #007bff;
            margin-right: 15px;
        }}
        .navbar a:hover {{
            text-decoration: underline;
        }}
        input[type="text"], input[type="password"], input[type="url"], select {{
            width: 100%;
            padding: 8px;
            margin: 8px 0;
            display: inline-block;
            border: 1px solid #ccc;
            border-radius: 4px;
            box-sizing: border-box;
        }}
        button, input[type="submit"] {{
            background-color: #4CAF50;
            color: white;
            padding: 10px 15px;
            margin: 8px 0;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }}
        button:hover, input[type="submit"]:hover {{
            background-color: #45a049;
        }}
        .error {{
            color: red;
            margin-bottom: 15px;
        }}
        .success {{
            color: green;
            margin-bottom: 15px;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
        }}
        th, td {{
            text-align: left;
            padding: 8px;
            border-bottom: 1px solid #ddd;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        .bookmark-category {{
            margin-top: 20px;
            padding: 10px;
            background-color: #f8f9fa;
            border-radius: 4px;
        }}
        .share-url {{
            font-size: 0.9em;
            color: #666;
            word-break: break-all;
        }}
        .actions a, .actions button {{
            margin-right: 5px;
            text-decoration: none;
            font-size: 0.9em;
        }}
        .hidden {{
            display: none;
        }}
    </style>
</head>
<body>
    <div class="navbar">
        <div>
            <a href="/">Bookmark Manager</a>
            {f'<span>Hello, {html.escape(username)}</span>' if username else ''}
        </div>
        <div>
            {f'<a href="/add">Add Bookmark</a><a href="/logout">Logout</a>' if user_id else '<a href="/login">Login</a><a href="/register">Register</a>'}
        </div>
    </div>
    <h1>{title}</h1>
    {content}
</body>
</html>
"""

def login_page(error=None):
    """Render the login page"""
    content = f"""
    {f'<p class="error">{error}</p>' if error else ''}
    <form method="post" action="/login">
        <div>
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required>
        </div>
        <div>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required>
        </div>
        <div>
            <input type="submit" value="Login">
        </div>
    </form>
    <p>Don't have an account? <a href="/register">Register</a></p>
    """
    return render_template("Login", content)

def register_page(error=None):
    """Render the registration page"""
    content = f"""
    {f'<p class="error">{error}</p>' if error else ''}
    <form method="post" action="/register">
        <div>
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required>
        </div>
        <div>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required>
        </div>
        <div>
            <label for="confirm_password">Confirm Password:</label>
            <input type="password" id="confirm_password" name="confirm_password" required>
        </div>
        <div>
            <input type="submit" value="Register">
        </div>
    </form>
    <p>Already have an account? <a href="/login">Login</a></p>
    """
    return render_template("Register", content)

def bookmarks_page(user_id, message=None):
    """Render the bookmarks page for a user"""
    bookmarks = get_user_bookmarks(user_id)
    
    # Group bookmarks by category
    bookmarks_by_category = {}
    for bookmark in bookmarks:
        category = bookmark["category"] or "Uncategorized"
        if category not in bookmarks_by_category:
            bookmarks_by_category[category] = []
        bookmarks_by_category[category].append(bookmark)
    
    # Build the content
    content = ""
    if message:
        if "error" in message.lower():
            content += f'<p class="error">{message}</p>'
        else:
            content += f'<p class="success">{message}</p>'
    
    if not bookmarks:
        content += """
        <p>You don't have any bookmarks yet.</p>
        <p><a href="/add">Add your first bookmark</a></p>
        """
    else:
        share_base_url = f"http://{HOST}:{PORT}/shared/"
        
        for category, cat_bookmarks in sorted(bookmarks_by_category.items()):
            content += f'<div class="bookmark-category"><h2>{html.escape(category)}</h2>'
            content += '<table>'
            content += '<tr><th>Title</th><th>URL</th><th>Visit Count</th><th>Actions</th></tr>'
            
            for bookmark in cat_bookmarks:
                share_url = f"{share_base_url}{bookmark['share_id']}" if bookmark['share_id'] else None
                
                content += f"""
                <tr>
                    <td>{html.escape(bookmark["title"])}</td>
                    <td><a href="/go/{bookmark["id"]}" target="_blank">{html.escape(bookmark["url"])}</a></td>
                    <td>{bookmark["visit_count"]}</td>
                    <td class="actions">
                        <a href="/edit/{bookmark["id"]}">Edit</a>
                        <form method="post" action="/delete/{bookmark["id"]}" style="display:inline">
                            <button type="submit" onclick="return confirm('Are you sure?')">Delete</button>
                        </form>
                        <form method="post" action="/share/{bookmark["id"]}" style="display:inline">
                            <button type="submit">{'View Share Link' if bookmark['share_id'] else 'Generate Share Link'}</button>
                        </form>
                    </td>
                </tr>
                {f'<tr><td colspan="4" class="share-url">Share URL: <a href="{share_url}" target="_blank">{share_url}</a></td></tr>' if share_url else ''}
                """
            
            content += '</table></div>'
    
    return render_template("My Bookmarks", content, user_id)

def add_bookmark_page(user_id, error=None):
    """Render the add bookmark page"""
    # Get categories from user's existing bookmarks
    bookmarks = get_user_bookmarks(user_id)
    categories = sorted(set(b["category"] for b in bookmarks if b["category"]))
    
    categories_options = ''.join(f'<option value="{html.escape(category)}">{html.escape(category)}</option>' for category in categories)
    
    content = f"""
    {f'<p class="error">{error}</p>' if error else ''}
    <form method="post" action="/add">
        <div>
            <label for="title">Title:</label>
            <input type="text" id="title" name="title" required>
        </div>
        <div>
            <label for="url">URL:</label>
            <input type="url" id="url" name="url" required>
        </div>
        <div>
            <label for="category">Category:</label>
            <input type="text" id="category" name="category" list="categories">
            <datalist id="categories">
                {categories_options}
            </datalist>
        </div>
        <div>
            <input type="submit" value="Add Bookmark">
        </div>
    </form>
    <p><a href="/">Back to bookmarks</a></p>
    """
    return render_template("Add Bookmark", content, user_id)

def edit_bookmark_page(user_id, bookmark_id, error=None):
    """Render the edit bookmark page"""
    bookmark = get_bookmark_by_id(bookmark_id, user_id)
    if not bookmark:
        return None
    
    # Get categories from user's existing bookmarks
    bookmarks = get_user_bookmarks(user_id)
    categories = sorted(set(b["category"] for b in bookmarks if b["category"]))
    
    categories_options = ''.join(f'<option value="{html.escape(category)}">{html.escape(category)}</option>' for category in categories)
    
    content = f"""
    {f'<p class="error">{error}</p>' if error else ''}
    <form method="post" action="/edit/{bookmark_id}">
        <div>
            <label for="title">Title:</label>
            <input type="text" id="title" name="title" value="{html.escape(bookmark['title'])}" required>
        </div>
        <div>
            <label for="url">URL:</label>
            <input type="url" id="url" name="url" value="{html.escape(bookmark['url'])}" required>
        </div>
        <div>
            <label for="category">Category:</label>
            <input type="text" id="category" name="category" value="{html.escape(bookmark['category'] or '')}" list="categories">
            <datalist id="categories">
                {categories_options}
            </datalist>
        </div>
        <div>
            <input type="submit" value="Update Bookmark">
        </div>
    </form>
    <p><a href="/">Back to bookmarks</a></p>
    """
    return render_template(f"Edit Bookmark: {bookmark['title']}", content, user_id)

def shared_bookmark_page(bookmark):
    """Render a shared bookmark page"""
    username = get_username_by_id(bookmark["user_id"])
    
    content = f"""
    <div>
        <h2>{html.escape(bookmark["title"])}</h2>
        <p>Shared by: {html.escape(username)}</p>
        <p>Visits: {bookmark["visit_count"]}</p>
        <p><a href="{html.escape(bookmark["url"])}" target="_blank">{html.escape(bookmark["url"])}</a></p>
    </div>
    """
    return render_template(f"Shared Bookmark: {bookmark['title']}", content)

# HTTP Request Handler
class BookmarkHandler(http.server.SimpleHTTPRequestHandler):
    def send_response_with_cookies(self, code, cookies_dict=None):
        """Send a response with cookies"""
        self.send_response(code)
        
        if cookies_dict:
            for key, value in cookies_dict.items():
                cookie = cookies.SimpleCookie()
                cookie[key] = value
                cookie[key]["path"] = "/"
                # If key is session_id, set expiration
                if key == "session_id":
                    # Set cookie to expire in 24 hours
                    cookie[key]["expires"] = (datetime.datetime.now() + datetime.timedelta(days=1)).strftime("%a, %d %b %Y %H:%M:%S GMT")
                self.send_header("Set-Cookie", cookie.output(header='', sep=''))
    
    def get_session_id(self):
        """Get the session ID from cookies"""
        if "Cookie" in self.headers:
            cookie = cookies.SimpleCookie(self.headers["Cookie"])
            if "session_id" in cookie:
                return cookie["session_id"].value
        return None
    
    def authenticate(self):
        """Authenticate the user from session cookie"""
        session_id = self.get_session_id()
        if session_id:
            return validate_session(session_id)
        return None
        
    def send_error_page(self, code, message):
        """Send an error page with the given code and message"""
        self.send_response(code)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        
        content = f"""
        <p>{message}</p>
        <p><a href="/">Back to home</a></p>
        """
        self.wfile.write(render_template(f"Error {code}", content).encode())
    
    def send_redirect(self, location, cookies_dict=None):
        """Send a redirect to the given location with optional cookies"""
        self.send_response_with_cookies(303, cookies_dict)
        self.send_header("Location", location)
        self.end_headers()
    
    def parse_post_data(self):
        """Parse POST data from request body"""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        return parse_qs(post_data)
    
    def require_login(self):
        """Require login for a page, redirects to login if not authenticated"""
        user_id = self.authenticate()
        if not user_id:
            self.send_redirect("/login")
            return None
        return user_id
    
    def do_GET(self):
        """Handle GET requests"""
        url = urlparse(self.path)
        path = url.path
        
        # Handle static files (for favicon, etc.)
        if path.startswith("/static/"):
            return super().do_GET()
        
        # Root/home page
        if path == "/" or path == "/index.html":
            user_id = self.authenticate()
            if user_id:
                # Show user's bookmarks
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bookmarks_page(user_id).encode())
            else:
                # Show login page
                self.send_redirect("/login")
        
        # Login page
        elif path == "/login":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(login_page().encode())
        
        # Register page
        elif path == "/register":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(register_page().encode())
        
        # Logout
        elif path == "/logout":
            # Clear session cookie
            self.send_redirect("/", {"session_id": ""})
        
        # Add bookmark page
        elif path == "/add":
            user_id = self.require_login()
            if not user_id:
                return
            
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(add_bookmark_page(user_id).encode())
        
        # Edit bookmark page
        elif path.startswith("/edit/"):
            user_id = self.require_login()
            if not user_id:
                return
            
            bookmark_id = path.split("/")[-1]
            try:
                bookmark_id = int(bookmark_id)
            except ValueError:
                self.send_error_page(400, "Invalid bookmark ID")
                return
            
            page = edit_bookmark_page(user_id, bookmark_id)
            if not page:
                self.send_error_page(404, "Bookmark not found")
                return
            
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(page.encode())
        
        # Go to bookmark URL
        elif path.startswith("/go/"):
            user_id = self.require_login()
            if not user_id:
                return
            
            bookmark_id = path.split("/")[-1]
            try:
                bookmark_id = int(bookmark_id)
            except ValueError:
                self.send_error_page(400, "Invalid bookmark ID")
                return
            
            bookmark = get_bookmark_by_id(bookmark_id, user_id)
            if not bookmark:
                self.send_error_page(404, "Bookmark not found")
                return
            
            # Increment visit count
            increment_visit_count(bookmark_id)
            
            # Redirect to the bookmark URL
            self.send_redirect(bookmark["url"])
        
        # Shared bookmark page
        elif path.startswith("/shared/"):
            share_id = path.split("/")[-1]
            bookmark = get_bookmark_by_share_id(share_id)
            
            if not bookmark:
                self.send_error_page(404, "Shared bookmark not found")
                return
            
            # Increment visit count
            increment_visit_count(bookmark["id"])
            
            # Show the shared bookmark page
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(shared_bookmark_page(bookmark).encode())
        
        # Not found
        else:
            self.send_error_page(404, "Page not found")
    
    def do_POST(self):
        """Handle POST requests"""
        url = urlparse(self.path)
        path = url.path
        
        # Login
        if path == "/login":
            post_data = self.parse_post_data()
            username = post_data.get("username", [""])[0]
            password = post_data.get("password", [""])[0]
            
            user_id = authenticate_user(username, password)
            if user_id:
                # Create session
                session_id = create_session(user_id)
                self.send_redirect("/", {"session_id": session_id})
            else:
                # Show login page with error
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(login_page("Invalid username or password").encode())
        
        # Register
        elif path == "/register":
            post_data = self.parse_post_data()
            username = post_data.get("username", [""])[0]
            password = post_data.get("password", [""])[0]
            confirm_password = post_data.get("confirm_password", [""])[0]
            
            # Validate inputs
            if not username or not password:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(register_page("Username and password are required").encode())
                return
            
            if password != confirm_password:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(register_page("Passwords do not match").encode())
                return
            
            # Create the user
            success = create_user(username, password)
            if success:
                # Authenticate and create session
                user_id = authenticate_user(username, password)
                session_id = create_session(user_id)
                self.send_redirect("/", {"session_id": session_id})
            else:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(register_page("Username already exists").encode())
        
        # Add bookmark
        elif path == "/add":
            user_id = self.require_login()
            if not user_id:
                return
            
            post_data = self.parse_post_data()
            title = post_data.get("title", [""])[0]
            url = post_data.get("url", [""])[0]
            category = post_data.get("category", [""])[0] or None
            
            # Validate inputs
            if not title or not url:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(add_bookmark_page(user_id, "Title and URL are required").encode())
                return
            
            # Add the bookmark
            add_bookmark(user_id, title, url, category)
            self.send_redirect("/")
        
        # Edit bookmark
        elif path.startswith("/edit/"):
            user_id = self.require_login()
            if not user_id:
                return
            
            bookmark_id = path.split("/")[-1]
            try:
                bookmark_id = int(bookmark_id)
            except ValueError:
                self.send_error_page(400, "Invalid bookmark ID")
                return
            
            post_data = self.parse_post_data()
            title = post_data.get("title", [""])[0]
            url = post_data.get("url", [""])[0]
            category = post_data.get("category", [""])[0] or None
            
            # Validate inputs
            if not title or not url:
                page = edit_bookmark_page(user_id, bookmark_id, "Title and URL are required")
                if not page:
                    self.send_error_page(404, "Bookmark not found")
                    return
                
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(page.encode())
                return
            
            # Update the bookmark
            success = update_bookmark(bookmark_id, user_id, title, url, category)
            if not success:
                self.send_error_page(404, "Bookmark not found")
                return
            
            self.send_redirect("/")
        
        # Delete bookmark
        elif path.startswith("/delete/"):
            user_id = self.require_login()
            if not user_id:
                return
            
            bookmark_id = path.split("/")[-1]
            try:
                bookmark_id = int(bookmark_id)
            except ValueError:
                self.send_error_page(400, "Invalid bookmark ID")
                return
            
            # Delete the bookmark
            success = delete_bookmark(bookmark_id, user_id)
            if not success:
                self.send_error_page(404, "Bookmark not found")
                return
            
            self.send_redirect("/")
        
        # Share bookmark (generate share link)
        elif path.startswith("/share/"):
            user_id = self.require_login()
            if not user_id:
                return
            
            bookmark_id = path.split("/")[-1]
            try:
                bookmark_id = int(bookmark_id)
            except ValueError:
                self.send_error_page(400, "Invalid bookmark ID")
                return
            
            # Generate or get share ID
            share_id = generate_share_id(bookmark_id, user_id)
            if not share_id:
                self.send_error_page(404, "Bookmark not found")
                return
            
            self.send_redirect("/")
        
        # Not found
        else:
            self.send_error_page(404, "Page not found")

def run_server():
    """Run the HTTP server"""
    handler = BookmarkHandler
    with socketserver.ThreadingTCPServer((HOST, PORT), handler) as httpd:
        print(f"Server running at http://{HOST}:{PORT}")
        httpd.serve_forever()

if __name__ == "__main__":
    # Initialize the database
    init_db()
    
    # Start the scheduler
    start_scheduler()
    
    # Run the server
    run_server()
# ```

# This single-file Python application implements a private bookmark manager with all the requested features:

# 1. **Authentication**: Users can register and login with username/password
# 2. **Bookmark Management**: Users can add, edit, and delete bookmarks with categories
# 3. **Bookmark Redirection**: Clicking a bookmark redirects to the external URL, while unauthenticated access redirects to /login
# 4. **Sharing**: Users can generate shareable URLs for bookmarks, accessible without authentication; visits are tracked
# 5. **Daily Downloads**: A scheduler runs at 2 AM to download all bookmarks as HTML and save them as tar files
# 6. **External Notification**: The system calls /usr/bin/send with the tar filename to send it to users

# To run this application:
# 1. Save the code to a file (e.g., `bookmark_manager.py`)
# 2. Make it executable: `chmod +x bookmark_manager.py`
# 3. Run it: `./bookmark_manager.py`

# The server will start on http://localhost:8000 by default.