# test_app.py
from flask import Flask, request, render_template_string, g, session, redirect, jsonify
import sqlite3
import os
import requests
import xml.etree.ElementTree as ET

try:
    from flask_socketio import SocketIO, emit
    SOCKET_AVAILABLE = True
except ImportError:
    SOCKET_AVAILABLE = False

app = Flask(__name__)
app.secret_key = 'insecure_secret_key'  # intentionally insecure for demonstration

if SOCKET_AVAILABLE:
    socketio = SocketIO(app)

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def init_db():
    db = sqlite3.connect('test.db')
    db.execute('''CREATE TABLE IF NOT EXISTS messages
                  (id INTEGER PRIMARY KEY, message TEXT)''')
    db.commit()
    return db
def test_endpoint(url):
    print(f"Testing endpoint: {url}")
    response = make_request(url)
    if response:
        print(f"Response from {url}: {response.status_code}")
    time.sleep(1)  # Delay to avoid overwhelming the server


def make_request(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
        "Upgrade-Insecure-Requests": "1"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()  # Raise an error for bad responses
        return response
    except requests.exceptions.RequestException as e:
        print(f"Error making request to {url}: {e}")
        return None

BASE_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Test Application</title>
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    
    <!-- Update Bootstrap CSS with latest version and correct integrity -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" 
          rel="stylesheet" 
          integrity="sha384-9ndCyUaIbzAi2FUVXJi0CjmCapSmO7SnpJef0486qhLnuZ2cdeRhO02iuK6FUUVM" 
          crossorigin="anonymous">
    
    <!-- Add Bootstrap Icons -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css">
    
    <!-- Add Toastr CSS from CDN -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/toastr.js/latest/toastr.min.css">
    
    <!-- Add Toastify CSS and JS -->
    <link rel="stylesheet" type="text/css" href="https://cdn.jsdelivr.net/npm/toastify-js/src/toastify.min.css">
    <script type="text/javascript" src="https://cdn.jsdelivr.net/npm/toastify-js"></script>

    <!-- Custom Style -->
    <style>
        /* Increase base font size */
        body {
          font-size: 1.65rem; 
          padding-top: 70px;  
        }
        footer {
          margin-top: 50px;
          text-align: center;
          color: #777;
        }
        .nav-flex {
        display: flex !important;
        justify-content: space-between !important;
        align-items: center !important;
      }
        /* Toastify custom styles */
        .toastify {
            font-size: 1rem;
            padding: 12px 20px;
            box-shadow: 0 3px 6px rgba(0,0,0,0.16);
        }
        .toast-success {
            background: linear-gradient(to right, #00b09b, #96c93d);
        }
        .toast-error {
            background: linear-gradient(to right, #ff5f6d, #ffc371);
        }
        .toast-info {
            background: linear-gradient(to right, #2193b0, #6dd5ed);
        }
    </style>
</head>
<body>
  <!-- Navigation Bar -->
  <nav class="navbar navbar-expand-md  navbar-dark bg-dark fixed-top">
    <a class="navbar-brand" href="/">Test App</a>
    <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" 
            aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
      <span class="navbar-toggler-icon"></span>
    </button>
  
    <div class="collapse navbar-collapse" id="navbarNav">
      <ul class="navbar-nav mr-auto">
        <li class="nav-item"><a class="nav-link" href="/search">Search</a></li>
        <li class="nav-item"><a class="nav-link" href="/message">Leave Message</a></li>
        <li class="nav-item"><a class="nav-link" href="/login">Login</a></li>
      </ul>
    </div>
  </nav>
  
  <div class="container">
    <h1 class="mt-4">Test Application</h1>
    <hr>

    <!-- First row of forms -->
    <div class="row">
      <!-- Left Column -->
      <div class="col-md-6">
        <!-- SQL Injection -->
        <div class="card mb-4">
          <div class="card-header">Search Messages (SQL Injection)</div>
          <div class="card-body">
            <form method="GET" action="/search">
              <div class="form-group">
                <input type="text" name="q" class="form-control" placeholder="Search messages...">
              </div>
              <button type="submit" class="btn btn-primary">Search</button>
            </form>
          </div>
        </div>

        <!-- NoSQL Injection -->
        <div class="card mb-4">
          <div class="card-header">NoSQL Injection Test</div>
          <div class="card-body">
            <form method="GET" action="/nosql_search">
              <div class="form-group">
                <input type="text" name="q" class="form-control" placeholder="Enter NoSQL query...">
              </div>
              <button type="submit" class="btn btn-primary">Search</button>
            </form>
          </div>
        </div>

        <!-- Stored XSS -->
        <div class="card mb-4">
          <div class="card-header">Leave a Message (Stored XSS)</div>
          <div class="card-body">
            <form method="POST" action="/message">
              <div class="form-group">
                <input type="text" name="message" class="form-control" placeholder="Enter your message...">
              </div>
              <button type="submit" class="btn btn-primary">Submit Message</button>
            </form>
          </div>
        </div>

        <!-- DOM XSS -->
        <div class="card mb-4">
          <div class="card-header">DOM XSS Test</div>
          <div class="card-body">
            <form method="GET" action="/dom">
              <div class="form-group">
                <input type="text" name="data" class="form-control" placeholder="Enter data...">
              </div>
              <button type="submit" class="btn btn-primary">Submit Data</button>
            </form>
          </div>
        </div>
      </div>

      <!-- Right Column -->
      <div class="col-md-6">
        <!-- LDAP Injection -->
        <div class="card mb-4">
          <div class="card-header">LDAP Injection Test</div>
          <div class="card-body">
            <form method="GET" action="/ldap">
              <div class="form-group">
                <input type="text" name="username" class="form-control" placeholder="Enter username...">
              </div>
              <button type="submit" class="btn btn-primary">Search LDAP</button>
            </form>
          </div>
        </div>

        <!-- XXE Injection -->
        <div class="card mb-4">
          <div class="card-header">XXE Injection Test</div>
          <div class="card-body">
            <form method="POST" action="/xxe">
              <div class="form-group">
                <textarea name="xml" class="form-control" rows="5" placeholder="Enter XML..."></textarea>
              </div>
              <button type="submit" class="btn btn-primary">Submit XML</button>
            </form>
          </div>
        </div>

        <!-- Login -->
        <div class="card mb-4">
          <div class="card-header">Login (Authentication Vulnerability)</div>
          <div class="card-body">
            <form method="POST" action="/login">
              <div class="form-group">
                <input type="text" name="username" class="form-control" placeholder="Username">
              </div>
              <div class="form-group">
                <input type="password" name="password" class="form-control" placeholder="Password">
              </div>
              <button type="submit" class="btn btn-primary">Login</button>
            </form>
          </div>
        </div>

        <!-- Password Reset -->
        <div class="card mb-4">
          <div class="card-header">Password Reset (Insecure)</div>
          <div class="card-body">
            <form method="POST" action="/reset">
              <div class="form-group">
                <input type="text" name="username" class="form-control" placeholder="Username">
              </div>
              <button type="submit" class="btn btn-primary">Reset Password</button>
            </form>
          </div>
        </div>
      </div>
    </div>

    <!-- Second row of forms -->
    <div class="row">
      <!-- Left Column -->
      <div class="col-md-6">
        <!-- IDOR -->
        <div class="card mb-4">
          <div class="card-header">View Profile (IDOR)</div>
          <div class="card-body">
            <form method="GET" action="/profile/1" class="mb-2">
              <button type="submit" class="btn btn-primary">View Profile 1</button>
            </form>
            <form method="GET" action="/profile/2">
              <button type="submit" class="btn btn-primary">View Profile 2</button>
            </form>
          </div>
        </div>

        <!-- Privilege Escalation -->
        <div class="card mb-4">
          <div class="card-header">Admin Panel (Privilege Escalation)</div>
          <div class="card-body">
            <form method="GET" action="/admin">
              <button type="submit" class="btn btn-danger">Go to Admin Panel</button>
            </form>
          </div>
        </div>

        <!-- File Upload -->
        <div class="card mb-4">
          <div class="card-header">File Upload</div>
          <div class="card-body">
            <form method="POST" action="/upload" enctype="multipart/form-data">
              <div class="form-group">
                <input type="file" name="file" class="form-control-file">
              </div>
              <button type="submit" class="btn btn-primary">Upload File</button>
            </form>
          </div>
        </div>

        <!-- File Inclusion -->
        <div class="card mb-4">
          <div class="card-header">File Inclusion</div>
          <div class="card-body">
            <form method="GET" action="/include">
              <div class="form-group">
                <input type="text" name="file" class="form-control" placeholder="Enter filename...">
              </div>
              <button type="submit" class="btn btn-primary">Include File</button>
            </form>
          </div>
        </div>
      </div>

      <!-- Right Column -->
      <div class="col-md-6">
        <!-- SSRF -->
        <div class="card mb-4">
          <div class="card-header">SSRF Test</div>
          <div class="card-body">
            <form method="GET" action="/ssrf">
              <div class="form-group">
                <input type="text" name="url" class="form-control" placeholder="Enter URL...">
              </div>
              <button type="submit" class="btn btn-primary">Fetch URL</button>
            </form>
          </div>
        </div>

        <!-- API Abuse -->
        <div class="card mb-4">
          <div class="card-header">API Data (No Rate Limiting)</div>
          <div class="card-body">
            <form method="GET" action="/api/data">
              <button type="submit" class="btn btn-primary">Get API Data</button>
            </form>
          </div>
        </div>
      </div>
    </div>
    
    <!-- Remove Messages Section -->
    
    <!-- Search Query Section -->
    {% if search_query %}
      <div class="card mb-4">
        <div class="card-header">Search Results</div>
        <div class="card-body">
          <h5>Search Results for: {{ search_query|safe }}</h5>
        </div>
      </div>
    {% endif %}
    
    <!-- WebSocket Message Section -->
    {% if ws_message %}
      <div class="card mb-4">
        <div class="card-header">WebSocket Message</div>
        <div class="card-body">
          <div class="alert alert-warning">{{ ws_message }}</div>
        </div>
      </div>
    {% endif %}
  </div>
  
  <footer class="container">
    <p>&copy; 2025 Test Application. All rights reserved.</p>
  </footer>
  
  <!-- Update JavaScript dependencies -->
  <script src="https://code.jquery.com/jquery-3.7.0.min.js"
          integrity="sha384-NXgwF8Kv9SSAr+jemKKcbvQsz+teULH/dRtq6VMRd/KB6n2yh8lpF6QUYokmQy+1"
          crossorigin="anonymous"></script>
          
  <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.8/dist/umd/popper.min.js"
          integrity="sha384-I7E8VVD/ismYTF4hNIPjVp/Zjvgyol6VFvRkX/vR+Vc4jQkC+hVqc2pM8ODewa9r"
          crossorigin="anonymous"></script>
          
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.min.js"
          integrity="sha384-fbbOQedDUMZZ5KreZpsbe1LCZPVmfTnH7ois6mU1QK+m14rQ1l2bGBq41eYeM/fS"
          crossorigin="anonymous"></script>
          
  <!-- Add Toastr JS from CDN -->
  <script src="https://cdnjs.cloudflare.com/ajax/libs/toastr.js/latest/toastr.min.js"></script>

  <!-- Add notification helper functions -->
  <script>
      // Notification helper functions
      const notify = {
          success: (message) => {
              Toastify({
                  text: message,
                  duration: 3000,
                  gravity: "top",
                  position: "right",
                  className: "toast-success",
                  stopOnFocus: true
              }).showToast();
          },
          error: (message) => {
              Toastify({
                  text: message,
                  duration: 3000,
                  gravity: "top",
                  position: "right",
                  className: "toast-error",
                  stopOnFocus: true
              }).showToast();
          },
          info: (message) => {
              Toastify({
                  text: message,
                  duration: 3000,
                  gravity: "top",
                  position: "right",
                  className: "toast-info",
                  stopOnFocus: true
              }).showToast();
          }
      };

      // Replace console.log with notify.info for XSS detection
      const originalLog = console.log;
      console.log = function(message) {
          if (typeof message === 'string' && message.toLowerCase().includes('xss')) {
              notify.info('XSS Test: ' + message);
          }
          originalLog.apply(console, arguments);
      };

      // Handle XSS test inputs
      function handleXSSTest(input) {
          if (input && input.toLowerCase().includes('xss')) {
              notify.info('XSS Test: Input contains potential XSS payload');
          }
      }

      // Add event listeners to inputs
      document.addEventListener('DOMContentLoaded', () => {
          document.querySelectorAll('input[type="text"], textarea').forEach(input => {
              input.addEventListener('change', (e) => handleXSSTest(e.target.value));
          });
      });

      // Handle form submissions
      document.querySelectorAll('form').forEach(form => {
          form.addEventListener('submit', (e) => {
              notify.info('Form submitted: ' + form.action);
          });
      });

      // Show notifications for successful actions
      {% if success_message %}
          notify.success("{{ success_message }}");
      {% endif %}
      
      {% if error_message %}
          notify.error("{{ error_message }}");
      {% endif %}
  </script>

  <!-- XSS testing functionality -->
  <script>
      // ... existing XSS test code ...
  </script>
</body>
</html>
'''

@app.before_request
def before_request():
    g.db = init_db()

@app.teardown_request
def teardown_request(exception):
    if hasattr(g, 'db'):
        g.db.close()

@app.route('/')
def home():
    messages = g.db.execute('SELECT message FROM messages').fetchall()
    return render_template_string(
        BASE_TEMPLATE,
        messages=[m[0] for m in messages]
    )

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Sanitize input by removing null characters
    query = query.replace('\x00', '')
    try:
        # Use parameterized query instead of string formatting
        results = g.db.execute(
            "SELECT message FROM messages WHERE message LIKE ?",
            ('%' + query + '%',)
        ).fetchall()
        
        return render_template_string(
            BASE_TEMPLATE,
            messages=[r[0] for r in results],
            search_query=query
        )
    except Exception as e:
        logging.error(f"Search error: {e}")
        return render_template_string(
            BASE_TEMPLATE,
            messages=[],
            error_message="An error occurred during search"
        )

@app.route('/nosql_search')
def nosql_search():
    q = request.args.get('q', '')
    try:
        # Vulnerable: using eval on user input (NoSQL injection simulation)
        results = eval(q)
    except Exception as e:
        results = str(e)
    return f"<div class='container mt-5'><h1>NoSQL Query Result</h1><pre>{results}</pre></div>"

@app.route('/message', methods=['POST'])
def message():
    message = request.form.get('message', '')
    g.db.execute('INSERT INTO messages (message) VALUES (?)', (message,))
    g.db.commit()
    return redirect('/')

@app.route('/dom')
def dom():
    data = request.args.get('data', '')
    dom_template = '''
    <!DOCTYPE html>
    <html>
    <head>
      <title>DOM XSS Demo</title>
      <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="container mt-5">
      <h1>DOM XSS Demo</h1>
      <script>
          // Vulnerable: user-supplied data is inserted directly into JS context.
          var userInput = "{{ data }}";
          document.write(userInput);
      </script>
    </body>
    </html>
    '''
    return render_template_string(dom_template, data=data)

@app.route('/ldap')
def ldap():
    username = request.args.get('username', '')
    # Vulnerable: constructing an LDAP filter without sanitization
    ldap_filter = f"(uid={username})"
    return f"<div class='container mt-5'><h1>LDAP Injection Test</h1><p>Constructed LDAP filter: {ldap_filter}</p></div>"

@app.route('/xxe', methods=['POST'])
def xxe():
    xml_data = request.form.get('xml', '')
    try:
        root = ET.fromstring(xml_data)
        return f"<div class='container mt-5'><h1>XXE Injection Test</h1><p>Parsed XML with root tag: {root.tag}</p></div>"
    except Exception as e:
        return f"<div class='container mt-5'><h1>XXE Injection Test</h1><p>Error parsing XML: {e}</p></div>"

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        if username == 'admin' and password == 'password':
            return render_template_string(BASE_TEMPLATE, 
                success_message='Logged in successfully!')
        else:
            return render_template_string(BASE_TEMPLATE, 
                error_message='Invalid credentials')
    return render_template_string(BASE_TEMPLATE)

@app.route('/reset', methods=['GET', 'POST'])
def reset():
    if request.method == 'POST':
        username = request.form.get('username', '')
        # Insecure: No verification, easily guessable token
        token = f"reset-{username}-token"
        return f"<div class='container mt-5'><h1>Password Reset</h1><p>Password reset link: <a href='http://127.0.0.1:5000/reset/{token}'>http://127.0.0.1:5000/reset/{token}</a></p></div>"
    return '''
    <div class="container mt-5">
      <h1>Password Reset</h1>
      <form method="POST" action="/reset">
        <div class="form-group">
          <label>Username:</label>
          <input type="text" class="form-control" name="username">
        </div>
        <button type="submit" class="btn btn-primary">Reset Password</button>
      </form>
    </div>
    '''

@app.route('/reset/<token>', methods=['GET', 'POST'])
def do_reset(token):
    if request.method == 'POST':
        new_password = request.form.get('password', '')
        return "<div class='container mt-5'><h1>Password Reset</h1><p>Password has been reset!</p></div>"
    return '''
    <div class="container mt-5">
      <h1>Set New Password</h1>
      <form method="POST" action="">
        <div class="form-group">
          <label>New Password:</label>
          <input type="password" class="form-control" name="password">
        </div>
        <button type="submit" class="btn btn-primary">Set New Password</button>
      </form>
    </div>
    '''

@app.route('/profile/<int:user_id>')
def profile(user_id):
    # Vulnerable: IDOR (no access control check)
    user = {"id": user_id, "username": f"user{user_id}", "email": f"user{user_id}@example.com"}
    return f"<div class='container mt-5'><h1>User Profile</h1><p>{user}</p></div>"

@app.route('/admin')
def admin():
    return "<div class='container mt-5'><h1>Admin Panel</h1><p>Welcome to the admin panel! (No access control)</p></div>"

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            return "<div class='container mt-5'><h1>File Upload</h1><p>No file part!</p></div>"
        file = request.files['file']
        if file.filename == '':
            return "<div class='container mt-5'><h1>File Upload</h1><p>No selected file!</p></div>"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)
        return f"<div class='container mt-5'><h1>File Upload</h1><p>File uploaded to {filepath}</p></div>"
    return '''
    <div class="container mt-5">
      <h1>File Upload</h1>
      <form method="POST" action="/upload" enctype="multipart/form-data">
        <div class="form-group">
          <input type="file" class="form-control-file" name="file">
        </div>
        <button type="submit" class="btn btn-primary">Upload</button>
      </form>
    </div>
    '''

@app.route('/include')
def include():
    filename = request.args.get('file', '')
    try:
        with open(filename, 'r') as f:
            content = f.read()
        return f"<div class='container mt-5'><h1>File Inclusion</h1><pre>{content}</pre></div>"
    except Exception as e:
        return f"<div class='container mt-5'><h1>File Inclusion</h1><p>Error including file: {e}</p></div>"

@app.route('/ssrf')
def ssrf():
    url = request.args.get('url', '')
    if url:
        try:
            r = requests.get(url)
            return f"<div class='container mt-5'><h1>SSRF Test</h1><pre>{r.text}</pre></div>"
        except Exception as e:
            return f"<div class='container mt-5'><h1>SSRF Test</h1><p>Error fetching URL: {e}</p></div>"
    return "<div class='container mt-5'><h1>SSRF Test</h1><p>No URL provided</p></div>"

if SOCKET_AVAILABLE:
    @app.route('/ws')
    def ws_index():
        return "<div class='container mt-5'><h1>WebSocket</h1><p>WebSocket endpoint - connect using a WebSocket client.</p></div>"

    @socketio.on('message')
    def handle_message(message):
        # Vulnerable: Echoes back any message
        emit('response', {'data': message})

@app.route('/api/data')
def api_data():
    data = {"data": "Sensitive data accessible without authentication or rate limiting."}
    return jsonify(data)

@app.before_request
def before_request():
    g.db = init_db()

@app.teardown_request
def teardown_request(exception):
    if hasattr(g, 'db'):
        g.db.close()

if __name__ == '__main__':
    if not os.path.exists('test.db'):
        init_db()
    
    if SOCKET_AVAILABLE:
        socketio.run(app, host='127.0.0.1', port=8000, debug=True)
    else:
        app.run(host='127.0.0.1', port=8000, debug=True)
