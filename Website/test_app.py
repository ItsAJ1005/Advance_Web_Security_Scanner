# test_app.py
from flask import Flask, request, render_template_string, g
import sqlite3
import os

app = Flask(__name__)

def init_db():
    db = sqlite3.connect('test.db')
    db.execute('''CREATE TABLE IF NOT EXISTS messages
                  (id INTEGER PRIMARY KEY, message TEXT)''')
    db.commit()
    return db

BASE_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Test Application</title>
</head>
<body>
    <h1>Test Application</h1>
    
    <!-- Test form for SQL injection -->
    <h2>Search Messages</h2>
    <form method="GET" action="/search">
        <input type="text" name="q" placeholder="Search messages...">
        <input type="submit" value="Search">
    </form>

    <!-- Test form for XSS -->
    <h2>Leave a Message</h2>
    <form method="POST" action="/message">
        <input type="text" name="message" placeholder="Enter your message...">
        <input type="submit" value="Submit">
    </form>

    <h2>Messages:</h2>
    {% if messages %}
        {% for message in messages %}
            <div>{{ message|safe }}</div>
        {% endfor %}
    {% endif %}

    {% if search_query %}
        <h3>Search Results for: {{ search_query|safe }}</h3>
    {% endif %}
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
    results = g.db.execute(
        f"SELECT message FROM messages WHERE message LIKE '%{query}%'"
    ).fetchall()
    
    return render_template_string(
        BASE_TEMPLATE,
        messages=[r[0] for r in results],
        search_query=query
    )

@app.route('/message', methods=['POST'])
def message():
    message = request.form.get('message', '')
    g.db.execute('INSERT INTO messages (message) VALUES (?)', (message,))
    g.db.commit()
    return app.redirect('/')

if __name__ == '__main__':
    if not os.path.exists('test.db'):
        init_db()
    app.run(host='127.0.0.1', port=5000, debug=False)