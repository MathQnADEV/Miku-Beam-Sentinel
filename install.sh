#!/bin/bash

# Miku Beam Sentinel - Installation Script
# Installs dependencies and sets up the 'miku-beam' command

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}[*] Miku Beam Sentinel Installer${NC}"

# Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Python 3 is not installed. Please install python3 first.${NC}"
    exit 1
fi

# Check for pip
if ! command -v pip3 &> /dev/null; then
    echo -e "${RED}[!] pip3 is not installed. Please install python3-pip first.${NC}"
    exit 1
fi

INSTALL_DIR=$(pwd)
VENV_DIR="$INSTALL_DIR/venv"

echo -e "${BLUE}[*] Setting up virtual environment in $VENV_DIR...${NC}"
# Try to create venv, fallback to system install if venv fails (common in Kali)
if ! python3 -m venv "$VENV_DIR"; then
    echo -e "${RED}[!] Failed to create venv. Attempting system-wide install...${NC}"
    pip3 install -r requirements.txt --break-system-packages
    pip3 install colorama termcolor --break-system-packages
else
    source "$VENV_DIR/bin/activate"
    echo -e "${BLUE}[*] Installing dependencies in venv...${NC}"
    pip install -r requirements.txt
    pip install colorama termcolor
fi

echo -e "${BLUE}[*] Setting up Frontend...${NC}"
cd web/frontend
if command -v npm &> /dev/null; then
    npm install
else
    echo -e "${RED}[!] npm is not installed. Frontend setup skipped.${NC}"
fi
cd ../..

echo -e "${BLUE}[*] Initializing database...${NC}"
cd web/backend
python manage.py migrate
cd ../..

# Create launcher script
LAUNCHER="$INSTALL_DIR/miku-beam"
echo -e "${BLUE}[*] Creating launcher script at $LAUNCHER...${NC}"

cat > "$LAUNCHER" <<EOF
#!/bin/bash
INSTALL_DIR="$INSTALL_DIR"
if [ -f "\$INSTALL_DIR/venv/bin/activate" ]; then
    source "\$INSTALL_DIR/venv/bin/activate"
fi
export PYTHONPATH="\$INSTALL_DIR"

if [ "\$1" == "--gui" ]; then
    echo -e "${GREEN}[*] Launching Miku Beam Sentinel Web Interface...${NC}"
    
    # Start Backend (ASGI via Daphne on 8001 — required for WebSocket scan stream)
    cd "\$INSTALL_DIR/web/backend"
    daphne -b 0.0.0.0 -p 8001 config.asgi:application > /dev/null 2>&1 &
    BACKEND_PID=\$!
    
    # Start Frontend
    cd "\$INSTALL_DIR/web/frontend"
    npm run dev > /dev/null 2>&1 &
    FRONTEND_PID=\$!
    
    echo -e "${BLUE}[*] Backend running (PID: \$BACKEND_PID)${NC}"
    echo -e "${BLUE}[*] Frontend running (PID: \$FRONTEND_PID)${NC}"
    echo -e "${GREEN}[+] Dashboard available at http://localhost:5173${NC}"
    echo -e "${BLUE}[*] Press Ctrl+C to stop servers${NC}"
    
    trap "kill \$BACKEND_PID \$FRONTEND_PID; exit" SIGINT
    wait
else
    # Run CLI
    python3 "\$INSTALL_DIR/cli/main.py" "\$@"
fi
EOF

chmod +x "$LAUNCHER"

echo -e "${GREEN}[+] Installation complete!${NC}"
echo -e "${BLUE}[*] To make 'miku-beam' accessible globally, run:${NC}"
echo -e "    sudo ln -s \"$LAUNCHER\" /usr/local/bin/miku-beam"
echo -e "${BLUE}[*] Usage:${NC}"
echo -e "    miku-beam --help"
echo -e "    miku-beam --gui"
