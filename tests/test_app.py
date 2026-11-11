import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
from app import create_app


class TaskboardTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.app = create_app(str(Path(self.directory.name) / 'tasks.db'))
        self.client = self.app.test_client()

    def tearDown(self):
        self.directory.cleanup()

    def test_health(self):
        self.assertEqual(self.client.get('/healthz').json, {'status': 'ok'})

    def test_add_and_toggle_task(self):
        response = self.client.post('/tasks', data={'title': 'Scan container'}, follow_redirects=True)
        self.assertIn(b'Scan container', response.data)
        self.client.post('/tasks/1/toggle')
        self.assertIn(b'class="done"', self.client.get('/').data)

    def test_invalid_titles(self):
        for title in ('', '   ', 'x' * 201):
            with self.subTest(title=title):
                self.assertEqual(self.client.post('/tasks', data={'title': title}).status_code, 400)

    def test_escaping_and_parameterised_database_query(self):
        response = self.client.post('/tasks', data={'title': "<script>alert('x')</script>"}, follow_redirects=True)
        self.assertIn(b'&lt;script&gt;', response.data)
        self.assertNotIn(b'<script>', response.data)
        self.client.post('/tasks', data={'title': "'); DROP TABLE tasks; --"})
        self.assertEqual(self.client.get('/').status_code, 200)

    def test_missing_task(self):
        self.assertEqual(self.client.post('/tasks/999/toggle').status_code, 404)

    def test_security_headers(self):
        response = self.client.get('/')
        self.assertEqual(response.headers['X-Content-Type-Options'], 'nosniff')
        self.assertIn("frame-ancestors 'none'", response.headers['Content-Security-Policy'])
