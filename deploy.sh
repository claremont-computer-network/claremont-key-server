#!/bin/bash
# Deploy Claremont Key Server to Production
set -e

echo "=== Deploying Claremont Key Server ==="

# Create data directories
sudo mkdir -p /data/key-server

# Pull latest code
cd /opt/claremont-key-server || (mkdir -p /opt/claremont-key-server && cd /opt/claremont-key-server && git clone https://github.com/claremont-computer-network/claremont-key-server.git .)
git pull

# Build and run with Docker
export DB_PATH=/data/key-server/keys.db
export SECRET_KEY=${SECRET_KEY:-key-server-secret-change-me}
export ADMIN_PASSWORD=${ADMIN_PASSWORD:-admin123}
export OPERATOR_PASSWORD=${OPERATOR_PASSWORD:-operator123}

docker build -t claremont-key-server:latest .
docker stop claremont-key-server 2>/dev/null || true
docker rm claremont-key-server 2>/dev/null || true
docker run -d \
    --name claremont-key-server \
    --restart unless-stopped \
    -p 5001:5001 \
    -v /data/key-server:/data \
    -e DB_PATH=/data/keys.db \
    -e SECRET_KEY="$SECRET_KEY" \
    -e ADMIN_PASSWORD="$ADMIN_PASSWORD" \
    -e OPERATOR_PASSWORD="$OPERATOR_PASSWORD" \
    claremont-key-server:latest

# Wait for startup
echo "Waiting for Key Server to start..."
sleep 10

# Health check
for i in {1..30}; do
    if curl -sf http://localhost:5001/api/v1/health > /dev/null; then
        echo "✅ Claremont Key Server is healthy!"
        curl -s http://localhost:5001/api/v1/health | python -m json.tool
        exit 0
    fi
    echo "Waiting... ($i/30)"
    sleep 2
done

echo "❌ Key Server failed to start"
docker logs claremont-key-server --tail=50
exit 1
