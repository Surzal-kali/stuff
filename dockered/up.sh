#!/bin/bash
set -e

# Build and start the workbench
docker compose up -d --build

# Wire the existing standalone chroma container into the workbench network
# so open-terminal can reach it by DNS name "chroma".
if docker network connect workbench chroma 2>/dev/null; then
    echo "[+] Connected chroma to workbench network"
else
    echo "[*] chroma already on workbench network (or container not found)"
fi

echo
echo "=== Workbench is up ==="
echo "  Open Terminal API : http://localhost:8000"
echo "  Framework gateway : http://localhost:6000"
echo
echo "  Open WebUI connection: Admin Settings -> Integrations -> Open Terminal"
echo "    URL: http://<this-host>:8000"
echo "    API key: whatever you set OPEN_TERMINAL_API_KEY to"
