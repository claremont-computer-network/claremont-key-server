#!/usr/bin/env python3
"""
Claremont Key Server
Enterprise API key and secrets management with Flask web UI and REST API.
"""

import os
import uuid
import json
import hashlib
import hmac
import datetime
import sqlite3
import requests
from cryptography.fernet import Fernet
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash
from functools import wraps

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'templates'))
app.secret_key = os.environ.get('SECRET_KEY', 'key-server-secret-change-in-production')

# Configuration
DB_PATH = os.environ.get('DB_PATH', os.path.join(BASE_DIR, 'data', 'keys.db'))
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', 'default-encryption-key-change-me')

# Derive Fernet key from ENCRYPTION_KEY (must be 32 url-safe base64-encoded bytes)
def _get_fernet():
    key = hashlib.sha256(ENCRYPTION_KEY.encode()).digest()
    import base64
    return Fernet(base64.urlsafe_b64encode(key))

_cipher = _get_fernet()

def encrypt_value(value):
    """Encrypt a secret value for storage."""
    return _cipher.encrypt(value.encode()).decode()

def decrypt_value(encrypted_value):
    """Decrypt a secret value from storage."""
    return _cipher.decrypt(encrypted_value.encode()).decode()

db_dir = os.path.dirname(DB_PATH)
if db_dir:
    os.makedirs(db_dir, exist_ok=True)

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS secrets (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        value TEXT NOT NULL,
        category TEXT DEFAULT 'general',
        environment TEXT DEFAULT 'production',
        created_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP,
        last_accessed TIMESTAMP,
        access_count INTEGER DEFAULT 0,
        description TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        secret_id TEXT,
        secret_name TEXT,
        action TEXT,
        user TEXT,
        ip_address TEXT,
        details TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS api_keys (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        key_hash TEXT NOT NULL,
        permissions TEXT DEFAULT 'read',
        created_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_used TIMESTAMP,
        is_active INTEGER DEFAULT 1,
        description TEXT
    )''')
    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def audit_log(secret_id, secret_name, action, user='system', details=''):
    db = get_db()
    db.execute('''INSERT INTO audit_log (secret_id, secret_name, action, user, ip_address, details)
                  VALUES (?, ?, ?, ?, ?, ?)''',
               (secret_id, secret_name, action, user, request.remote_addr if request else '', details))
    db.commit()
    db.close()

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Try CWS Bearer token first
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            cws_token = auth_header[7:]
            cws_url = os.environ.get('CWS_URL', 'http://ec2-54-89-192-212.compute-1.amazonaws.com:8000')
            try:
                resp = requests.get(
                    f'{cws_url}/api/user/info',
                    headers={'Authorization': f'Bearer {cws_token}'},
                    timeout=5
                )
                if resp.status_code == 200:
                    request.api_key = {'name': 'cws-bearer', 'id': 'cws-bearer'}
                    return f(*args, **kwargs)
            except Exception:
                pass
        
        # Fall back to X-API-Key
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        db = get_db()
        key = db.execute('SELECT * FROM api_keys WHERE key_hash = ? AND is_active = 1', (key_hash,)).fetchone()
        db.close()
        if not key:
            return jsonify({'error': 'Invalid or inactive API key'}), 401
        db = get_db()
        db.execute('UPDATE api_keys SET last_used = datetime("now") WHERE id = ?', (key['id'],))
        db.commit()
        db.close()
        request.api_key = key
        return f(*args, **kwargs)
    return decorated

# Web Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email') or request.form.get('username')
        api_key = request.form.get('api_key') or request.form.get('password')
        
        # Validate against claremontcomputer.net API
        CLAREMONT_API_URL = os.environ.get('CLAREMONT_API_URL', 'https://claremontcomputer.net')
        if email and api_key:
            try:
                import requests
                resp = requests.get(
                    f"{CLAREMONT_API_URL}/api/keys",
                    headers={"X-Api-Key": api_key},
                    timeout=10
                )
                if resp.status_code == 200:
                    session['user'] = email
                    session['api_key'] = api_key
                    session['auth_method'] = 'claremont_api'
                    return redirect(url_for('dashboard'))
            except Exception as e:
                print(f"API validation error: {e}")
            
            # Fallback to password auth
            valid_users = {
                'admin': os.environ.get('ADMIN_PASSWORD', 'admin123'),
                'operator': os.environ.get('OPERATOR_PASSWORD', 'operator123')
            }
            if email in valid_users and valid_users[email] == api_key:
                session['user'] = email
                session['auth_method'] = 'password'
                return redirect(url_for('dashboard'))
            flash('Invalid email or API key', 'error')
        else:
            flash('Email and API key required', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/')
@require_auth
def dashboard():
    db = get_db()
    stats = {
        'total_secrets': db.execute('SELECT COUNT(*) FROM secrets').fetchone()[0],
        'active_keys': db.execute('SELECT COUNT(*) FROM api_keys WHERE is_active = 1').fetchone()[0],
        'categories': db.execute('SELECT COUNT(DISTINCT category) FROM secrets').fetchone()[0],
        'recent_access': db.execute('SELECT COUNT(*) FROM secrets WHERE last_accessed > datetime("now", "-24 hours")').fetchone()[0]
    }
    recent_secrets = db.execute('SELECT * FROM secrets ORDER BY updated_at DESC LIMIT 10').fetchall()
    recent_audit = db.execute('SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 10').fetchall()
    db.close()
    return render_template('dashboard.html', stats=stats, recent_secrets=recent_secrets, recent_audit=recent_audit)

@app.route('/secrets')
@require_auth
def secrets_list():
    db = get_db()
    category = request.args.get('category')
    environment = request.args.get('environment')
    query = 'SELECT * FROM secrets WHERE 1=1'
    params = []
    if category:
        query += ' AND category = ?'
        params.append(category)
    if environment:
        query += ' AND environment = ?'
        params.append(environment)
    query += ' ORDER BY name ASC'
    secrets = db.execute(query, params).fetchall()
    categories = db.execute('SELECT DISTINCT category FROM secrets ORDER BY category').fetchall()
    environments = db.execute('SELECT DISTINCT environment FROM secrets ORDER BY environment').fetchall()
    db.close()
    return render_template('secrets.html', secrets=secrets, categories=categories, environments=environments,
                          selected_category=category, selected_environment=environment)

@app.route('/secrets/add', methods=['POST'])
@require_auth
def add_secret():
    secret_id = str(uuid.uuid4())[:8]
    name = request.form['name']
    value = encrypt_value(request.form['value'])
    category = request.form.get('category', 'general')
    environment = request.form.get('environment', 'production')
    description = request.form.get('description', '')
    expires_at = request.form.get('expires_at') or None
    db = get_db()
    try:
        db.execute('''INSERT INTO secrets (id, name, value, category, environment, description, expires_at, created_by)
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                   (secret_id, name, value, category, environment, description, expires_at, session.get('user')))
        db.commit()
        audit_log(secret_id, name, 'created', session.get('user'), f'Added to {category}/{environment}')
        flash(f'Secret "{name}" added', 'success')
    except sqlite3.IntegrityError:
        flash(f'Secret "{name}" already exists', 'error')
    db.close()
    return redirect(url_for('secrets_list'))

@app.route('/secrets/<secret_id>')
@require_auth
def secret_detail(secret_id):
    db = get_db()
    secret = db.execute('SELECT * FROM secrets WHERE id = ?', (secret_id,)).fetchone()
    if not secret:
        flash('Secret not found', 'error')
        return redirect(url_for('secrets_list'))
    db.close()
    return render_template('secret_detail.html', secret=secret)

@app.route('/secrets/<secret_id>/update', methods=['POST'])
@require_auth
def update_secret(secret_id):
    value = request.form.get('value')
    description = request.form.get('description', '')
    category = request.form.get('category', 'general')
    environment = request.form.get('environment', 'production')
    expires_at = request.form.get('expires_at') or None
    db = get_db()
    secret = db.execute('SELECT name FROM secrets WHERE id = ?', (secret_id,)).fetchone()
    if secret:
        db.execute('''UPDATE secrets SET value = ?, description = ?, category = ?, environment = ?,
                      expires_at = ?, updated_at = datetime("now") WHERE id = ?''',
                   (value, description, category, environment, expires_at, secret_id))
        db.commit()
        audit_log(secret_id, secret['name'], 'updated', session.get('user'), f'Updated in {category}/{environment}')
        flash('Secret updated', 'success')
    db.close()
    return redirect(url_for('secret_detail', secret_id=secret_id))

@app.route('/secrets/<secret_id>/delete', methods=['POST'])
@require_auth
def delete_secret(secret_id):
    db = get_db()
    secret = db.execute('SELECT name FROM secrets WHERE id = ?', (secret_id,)).fetchone()
    if secret:
        db.execute('DELETE FROM secrets WHERE id = ?', (secret_id,))
        db.commit()
        audit_log(secret_id, secret['name'], 'deleted', session.get('user'))
        flash(f'Secret "{secret["name"]}" deleted', 'success')
    db.close()
    return redirect(url_for('secrets_list'))

@app.route('/secrets/<secret_id>/rotate', methods=['POST'])
@require_auth
def rotate_secret(secret_id):
    new_value = str(uuid.uuid4())
    db = get_db()
    secret = db.execute('SELECT name FROM secrets WHERE id = ?', (secret_id,)).fetchone()
    if secret:
        db.execute('UPDATE secrets SET value = ?, updated_at = datetime("now") WHERE id = ?', (new_value, secret_id))
        db.commit()
        audit_log(secret_id, secret['name'], 'rotated', session.get('user'), 'Value rotated')
        flash(f'Secret "{secret["name"]}" rotated', 'success')
    db.close()
    return redirect(url_for('secret_detail', secret_id=secret_id))

@app.route('/api-keys')
@require_auth
def api_keys_list():
    db = get_db()
    keys = db.execute('SELECT * FROM api_keys ORDER BY created_at DESC').fetchall()
    db.close()
    return render_template('api_keys.html', keys=keys)

@app.route('/api-keys/generate', methods=['POST'])
@require_auth
def generate_api_key():
    raw_key = f'cks_{uuid.uuid4().hex}'
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key_id = str(uuid.uuid4())[:8]
    name = request.form.get('name', 'API Key')
    permissions = request.form.get('permissions', 'read')
    description = request.form.get('description', '')
    db = get_db()
    db.execute('''INSERT INTO api_keys (id, name, key_hash, permissions, description, created_by)
                  VALUES (?, ?, ?, ?, ?, ?)''',
               (key_id, name, key_hash, permissions, description, session.get('user')))
    db.commit()
    db.close()
    flash(f'API key generated: {raw_key} — save it now!', 'success')
    return redirect(url_for('api_keys_list'))

@app.route('/api-keys/<key_id>/toggle', methods=['POST'])
@require_auth
def toggle_api_key(key_id):
    db = get_db()
    key = db.execute('SELECT is_active FROM api_keys WHERE id = ?', (key_id,)).fetchone()
    if key:
        db.execute('UPDATE api_keys SET is_active = ? WHERE id = ?', (0 if key['is_active'] else 1, key_id))
        db.commit()
    db.close()
    return redirect(url_for('api_keys_list'))

@app.route('/api-keys/<key_id>/delete', methods=['POST'])
@require_auth
def delete_api_key(key_id):
    db = get_db()
    db.execute('DELETE FROM api_keys WHERE id = ?', (key_id,))
    db.commit()
    db.close()
    return redirect(url_for('api_keys_list'))

@app.route('/audit')
@require_auth
def audit_log_view():
    db = get_db()
    page = int(request.args.get('page', 1))
    per_page = 50
    offset = (page - 1) * per_page
    total = db.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0]
    logs = db.execute('SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ? OFFSET ?', (per_page, offset)).fetchall()
    db.close()
    return render_template('audit_log.html', logs=logs, page=page, total=total, per_page=per_page)

# API Endpoints
@app.route('/api/v1/secrets', methods=['GET'])
@require_api_key
def api_get_secrets():
    if request.api_key['permissions'] not in ('read', 'admin'):
        return jsonify({'error': 'Insufficient permissions'}), 403
    db = get_db()
    category = request.args.get('category')
    environment = request.args.get('environment', 'production')
    query = 'SELECT id, name, category, environment, created_at, updated_at, expires_at, access_count, description FROM secrets WHERE 1=1'
    params = []
    if category:
        query += ' AND category = ?'
        params.append(category)
    query += ' AND environment = ?'
    params.append(environment)
    secrets = db.execute(query, params).fetchall()
    db.close()
    return jsonify([{
        'id': s['id'], 'name': s['name'], 'category': s['category'],
        'environment': s['environment'], 'created_at': s['created_at'],
        'updated_at': s['updated_at'], 'expires_at': s['expires_at'],
        'access_count': s['access_count'], 'description': s['description']
    } for s in secrets])

@app.route('/api/v1/secrets/<name>', methods=['GET'])
@require_api_key
def api_get_secret(name):
    if request.api_key['permissions'] not in ('read', 'admin'):
        return jsonify({'error': 'Insufficient permissions'}), 403
    db = get_db()
    secret = db.execute('SELECT * FROM secrets WHERE name = ?', (name,)).fetchone()
    if not secret:
        db.close()
        return jsonify({'error': 'Secret not found'}), 404
    db.execute('UPDATE secrets SET last_accessed = datetime("now"), access_count = access_count + 1 WHERE id = ?', (secret['id'],))
    db.commit()
    db.close()
    return jsonify({
        'name': secret['name'], 'value': secret['value'],
        'category': secret['category'], 'environment': secret['environment'],
        'updated_at': secret['updated_at'], 'expires_at': secret['expires_at']
    })

@app.route('/api/v1/secrets', methods=['POST'])
@require_api_key
def api_create_secret():
    if request.api_key['permissions'] != 'admin':
        return jsonify({'error': 'Admin permission required'}), 403
    data = request.json
    if not data or not data.get('name') or not data.get('value'):
        return jsonify({'error': 'name and value are required'}), 400
    secret_id = str(uuid.uuid4())[:8]
    db = get_db()
    try:
        db.execute('''INSERT INTO secrets (id, name, value, category, environment, description, created_by)
                      VALUES (?, ?, ?, ?, ?, ?, 'api')''',
                   (secret_id, data['name'], data['value'],
                    data.get('category', 'general'), data.get('environment', 'production'),
                    data.get('description', '')))
        db.commit()
        db.close()
        return jsonify({'id': secret_id, 'name': data['name'], 'status': 'created'}), 201
    except sqlite3.IntegrityError:
        db.close()
        return jsonify({'error': 'Secret already exists'}), 409

@app.route('/api/v1/secrets/<name>', methods=['PUT'])
@require_api_key
def api_update_secret(name):
    if request.api_key['permissions'] != 'admin':
        return jsonify({'error': 'Admin permission required'}), 403
    data = request.json
    if not data or not data.get('value'):
        return jsonify({'error': 'value is required'}), 400
    db = get_db()
    secret = db.execute('SELECT id FROM secrets WHERE name = ?', (name,)).fetchone()
    if not secret:
        db.close()
        return jsonify({'error': 'Secret not found'}), 404
    db.execute('UPDATE secrets SET value = ?, updated_at = datetime("now") WHERE id = ?', (data['value'], secret['id']))
    db.commit()
    db.close()
    return jsonify({'name': name, 'status': 'updated'})

@app.route('/api/v1/secrets/<name>', methods=['DELETE'])
@require_api_key
def api_delete_secret(name):
    if request.api_key['permissions'] != 'admin':
        return jsonify({'error': 'Admin permission required'}), 403
    db = get_db()
    secret = db.execute('SELECT id FROM secrets WHERE name = ?', (name,)).fetchone()
    if not secret:
        db.close()
        return jsonify({'error': 'Secret not found'}), 404
    db.execute('DELETE FROM secrets WHERE id = ?', (secret['id'],))
    db.commit()
    db.close()
    return jsonify({'name': name, 'status': 'deleted'})

@app.route('/api/v1/health')
def api_health():
    try:
        db = get_db()
        db.execute('SELECT 1')
        db.close()
        return jsonify({'status': 'healthy', 'service': 'claremont-key-server'})
    except Exception:
        return jsonify({'status': 'unhealthy', 'service': 'claremont-key-server'}), 503

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=False)
