"""Small task tracker used as the container security pipeline's scan target."""

import os
import sqlite3
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, url_for


def create_app(database_path=None):
    app = Flask(__name__)
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024
    app.config['DATABASE'] = database_path or os.environ.get(
        'DATABASE_PATH', '/tmp/taskboard/tasks.db'
    )

    def connect():
        path = Path(app.config['DATABASE'])
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute(
            'CREATE TABLE IF NOT EXISTS tasks '
            '(id INTEGER PRIMARY KEY, title TEXT NOT NULL, done INTEGER NOT NULL DEFAULT 0)'
        )
        connection.commit()
        return connection

    @app.get('/healthz')
    def health():
        return jsonify(status='ok')

    @app.get('/')
    def index():
        connection = connect()
        try:
            tasks = connection.execute('SELECT * FROM tasks ORDER BY id DESC').fetchall()
        finally:
            connection.close()
        return render_template('index.html', tasks=tasks)

    @app.post('/tasks')
    def add_task():
        title = request.form.get('title', '').strip()
        if not title or len(title) > 200:
            return 'Task title must contain between 1 and 200 characters.', 400
        connection = connect()
        try:
            with connection:
                connection.execute('INSERT INTO tasks (title) VALUES (?)', (title,))
        finally:
            connection.close()
        return redirect(url_for('index'), code=303)

    @app.post('/tasks/<int:task_id>/toggle')
    def toggle_task(task_id):
        connection = connect()
        try:
            with connection:
                result = connection.execute(
                    'UPDATE tasks SET done = 1 - done WHERE id = ?', (task_id,)
                )
        finally:
            connection.close()
        if result.rowcount == 0:
            return 'Task not found.', 404
        return redirect(url_for('index'), code=303)

    @app.after_request
    def security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'"
        )
        return response

    return app
