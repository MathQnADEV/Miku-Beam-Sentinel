#!/bin/bash
# Startup script for Miku Beam Sentinel Backend with WebSocket support

echo "Starting Miku Beam Sentinel Backend with Daphne..."

# Get the directory of this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Activate virtual environment
source "$DIR/../../venv/bin/activate"

# Navigate to backend directory
cd "$DIR"

# Run migrations
echo "Running database migrations..."
python manage.py migrate

# Start Daphne server with WebSocket support (frontend expects port 8001)
echo "Starting Daphne server on 0.0.0.0:8001..."
daphne -b 0.0.0.0 -p 8001 config.asgi:application
