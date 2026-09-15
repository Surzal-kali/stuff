#!/bin/bash
set -e

# Build and start the workbench
docker compose up -d --build

echo
echo "=== Workbench is up ==="
echo "  Open Terminal API : http://localhost:8000"
echo "  Framework gateway : http://localhost:6000"

