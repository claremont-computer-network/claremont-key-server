#!/usr/bin/env python3
"""Tests for Claremont Key Server."""
import os
import tempfile
import unittest
from unittest.mock import patch

_test_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
_test_db.close()

os.environ['TESTING'] = 'true'
os.environ['DB_PATH'] = _test_db.name
os.environ['ADMIN_PASSWORD'] = 'testpass'

from app import app, init_db

class TestKeyServer(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()

    def test_login_page(self):
        resp = self.app.get('/login')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Key Server Login', resp.data)

    def test_login_failure(self):
        resp = self.app.post('/login', data={'username': 'admin', 'password': 'wrong'})
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Invalid', resp.data)

    def test_login_success(self):
        with patch.dict(os.environ, {'ADMIN_PASSWORD': 'testpass'}):
            resp = self.app.post('/login', data={'username': 'admin', 'password': 'testpass'}, follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b'Key Server', resp.data)

    def test_dashboard_requires_login(self):
        resp = self.app.get('/', follow_redirects=True)
        self.assertIn(b'Key Server Login', resp.data)

    def test_secrets_requires_login(self):
        resp = self.app.get('/secrets', follow_redirects=True)
        self.assertIn(b'Key Server Login', resp.data)

    def test_api_keys_requires_login(self):
        resp = self.app.get('/api-keys', follow_redirects=True)
        self.assertIn(b'Key Server Login', resp.data)

    def test_audit_requires_login(self):
        resp = self.app.get('/audit', follow_redirects=True)
        self.assertIn(b'Key Server Login', resp.data)

    def test_logout(self):
        with patch.dict(os.environ, {'ADMIN_PASSWORD': 'testpass'}):
            self.app.post('/login', data={'username': 'admin', 'password': 'testpass'})
            resp = self.app.get('/logout', follow_redirects=True)
            self.assertIn(b'Key Server Login', resp.data)

    def test_health_endpoint(self):
        resp = self.app.get('/api/v1/health')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['status'], 'healthy')

    def test_api_requires_key(self):
        resp = self.app.get('/api/v1/secrets')
        self.assertEqual(resp.status_code, 401)

    def test_secret_crud_flow(self):
        with patch.dict(os.environ, {'ADMIN_PASSWORD': 'testpass'}):
            # Login
            self.app.post('/login', data={'username': 'admin', 'password': 'testpass'})
            
            # Add secret
            resp = self.app.post('/secrets/add', data={
                'name': 'TEST_API_KEY',
                'value': 'test-secret-value-123',
                'category': 'testing',
                'environment': 'development',
                'description': 'Test secret'
            }, follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b'TEST_API_KEY', resp.data)
            
            # View secrets list
            resp = self.app.get('/secrets')
            self.assertIn(b'TEST_API_KEY', resp.data)

    def test_api_key_generation(self):
        with patch.dict(os.environ, {'ADMIN_PASSWORD': 'testpass'}):
            self.app.post('/login', data={'username': 'admin', 'password': 'testpass'})
            
            resp = self.app.post('/api-keys/generate', data={
                'name': 'Test Key',
                'permissions': 'read',
                'description': 'For testing'
            }, follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b'cks_', resp.data)

    def test_duplicate_secret(self):
        with patch.dict(os.environ, {'ADMIN_PASSWORD': 'testpass'}):
            self.app.post('/login', data={'username': 'admin', 'password': 'testpass'})
            
            self.app.post('/secrets/add', data={
                'name': 'UNIQUE_TEST_KEY',
                'value': 'value1',
                'category': 'test',
                'environment': 'test'
            })
            
            resp = self.app.post('/secrets/add', data={
                'name': 'UNIQUE_TEST_KEY',
                'value': 'value2',
                'category': 'test',
                'environment': 'test'
            }, follow_redirects=True)
            self.assertIn(b'already exists', resp.data)

if __name__ == '__main__':
    unittest.main()
