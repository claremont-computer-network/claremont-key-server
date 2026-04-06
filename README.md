# Claremont Key Server

Enterprise API key and secrets management system with Flask web UI and REST API.

## Features

- **Web UI** - Dark-themed dashboard for managing secrets, API keys, and audit logs
- **REST API** - Full CRUD for secrets with API key authentication (read/admin permissions)
- **Audit Logging** - Every action tracked with user, IP, timestamp, and details
- **Secret Rotation** - One-click value rotation with automatic audit trail
- **Category/Environment Filtering** - Organize secrets by category (aws, cloudflare, payments) and environment (production/staging/development)
- **Docker Deployable** - docker-compose.yml with named volume for persistent storage
- **CI/CD Ready** - `.cicd.yml` pipeline config for automated testing and deployment via cicd-deployer

## Quick Start

```bash
# Local development
pip install -r requirements.txt
python app.py

# Docker
docker compose up -d --build
```

## API Usage

```bash
# Get API key from UI, then:
curl -H "X-API-Key: cks_..." https://keys.claremontcomputer.net/api/v1/secrets
curl -H "X-API-Key: cks_..." https://keys.claremontcomputer.net/api/v1/secrets/STRIPE_KEY
```

## Deployment via CI/CD Deployer

1. Add as project in CI/CD Deployer UI
2. Set repo URL: `https://github.com/claremont-computer-network/claremont-key-server.git`
3. Merge PR → webhook triggers → tests run → Docker builds → deploys to production

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_PATH` | `./data/keys.db` | SQLite database path |
| `SECRET_KEY` | (auto) | Flask session secret |
| `ADMIN_PASSWORD` | `admin123` | Admin login password |
| `OPERATOR_PASSWORD` | `operator123` | Operator login password |
| `ENCRYPTION_KEY` | (auto) | Secret encryption key |
| `PORT` | `5001` | Server port |
