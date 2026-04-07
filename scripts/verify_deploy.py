#!/usr/bin/env python3
"""Verify DNS and health of deployed service."""
import os
import sys
import requests

DOMAIN = os.environ.get('VERIFY_DOMAIN', 'keys.claremontcomputer.net')
HEALTH_PATH = os.environ.get('VERIFY_HEALTH_PATH', '/api/v1/health')
PORT = int(os.environ.get('VERIFY_PORT', '5001'))

def verify_dns():
    """Check if domain resolves and returns 200."""
    url = f'https://{DOMAIN}/login'
    try:
        resp = requests.get(url, verify=False, timeout=10)
        logs.append(f"DNS check: {url} -> {resp.status_code}")
        return resp.status_code == 200
    except Exception as e:
        logs.append(f"DNS not yet available: {e}")
        return False

def verify_health():
    """Check health endpoint directly."""
    url = f'http://localhost:{PORT}{HEALTH_PATH}'
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            logs.append(f"Health check passed: {resp.json()}")
            return True
        logs.append(f"Health check returned {resp.status_code}")
        return False
    except Exception as e:
        logs.append(f"Health check failed: {e}")
        return False

# Run checks
dns_ok = verify_dns()
health_ok = verify_health()

if dns_ok:
    logs.append("✅ DNS verification passed")
elif health_ok:
    logs.append("✅ Service healthy (DNS may need propagation)")
else:
    logs.append("⚠️  Service not yet accessible via DNS")
