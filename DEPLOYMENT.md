# Deployment Guide - Miku Beam Sentinel

## Prerequisites

- Ubuntu/Debian Linux server
- Python 3.8+
- PostgreSQL 12+
- Nginx
- Node.js 16+
- Domain name (optional, for production)

## Production Deployment

### 1. Server Setup

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install PostgreSQL
sudo apt install postgresql postgresql-contrib -y

# Install Nginx
sudo apt install nginx -y

# Install Python and dependencies
sudo apt install python3-pip python3-venv -y

# Install Node.js
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install nodejs -y
```

### 2. Database Configuration

```bash
# Create PostgreSQL database and user
sudo -u postgres psql

CREATE DATABASE miku_beam_db;
CREATE USER miku_beam_user WITH PASSWORD 'your_secure_password';
ALTER ROLE miku_beam_user SET client_encoding TO 'utf8';
ALTER ROLE miku_beam_user SET default_transaction_isolation TO 'read committed';
ALTER ROLE miku_beam_user SET timezone TO 'UTC';
GRANT ALL PRIVILEGES ON DATABASE miku_beam_db TO miku_beam_user;
\q
```

### 3. Application Setup

```bash
# Clone repository
cd /opt
sudo git clone https://github.com/yourusername/miku-beam-sentinel.git
cd miku-beam-sentinel
sudo chown -R $USER:$USER .

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
pip install gunicorn psycopg2-binary
```

### 4. Django Configuration

Edit `web/backend/config/settings.py`:

```python
# Update for production
DEBUG = False
ALLOWED_HOSTS = ['your-domain.com', 'www.your-domain.com', 'server-ip']

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'miku_beam_db',
        'USER': 'miku_beam_user',
        'PASSWORD': 'your_secure_password',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}

# Security settings
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
```

### 5. Run Migrations

```bash
cd web/backend
python manage.py collectstatic --noinput
python manage.py migrate
python manage.py createsuperuser
```

### 6. Frontend Build

```bash
cd ../frontend

# Install dependencies
npm install

# Update API base URL in src/services/api.js
# Change to: const API_BASE_URL = 'https://your-domain.com/api';

# Build for production
npm run build
```

### 7. Systemd Service for Backend

Create `/etc/systemd/system/miku-beam-backend.service`:

```ini
[Unit]
Description=Miku Beam Sentinel Backend
After=network.target

[Service]
Type=notify
User=www-data
Group=www-data
RuntimeDirectory=gunicorn
WorkingDirectory=/opt/miku-beam-sentinel/web/backend
Environment="PATH=/opt/miku-beam-sentinel/venv/bin"
ExecStart=/opt/miku-beam-sentinel/venv/bin/gunicorn --workers 3 --bind unix:/run/gunicorn/miku-beam.sock config.wsgi:application
ExecReload=/bin/kill -s HUP $MAINPID
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable miku-beam-backend
sudo systemctl start miku-beam-backend
```

### 8. Nginx Configuration

Create `/etc/nginx/sites-available/miku-beam`:

```nginx
server {
    listen 80;
    server_name your-domain.com www.your-domain.com;

    # Frontend
    location / {
        root /opt/miku-beam-sentinel/web/frontend/dist;
        try_files $uri $uri/ /index.html;
    }

    # Backend API
    location /api {
        proxy_pass http://unix:/run/gunicorn/miku-beam.sock;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Admin
    location /admin {
        proxy_pass http://unix:/run/gunicorn/miku-beam.sock;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Static files
    location /static {
        alias /opt/miku-beam-sentinel/web/backend/staticfiles;
    }
}
```

Enable site:
```bash
sudo ln -s /etc/nginx/sites-available/miku-beam /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 9. SSL Certificate (Optional but Recommended)

```bash
sudo apt install certbot python3-certbot-nginx -y
sudo certbot --nginx -d your-domain.com -d www.your-domain.com
```

### 10. Firewall Configuration

```bash
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable
```

## Docker Deployment (Alternative)

### Dockerfile for Backend

Create `web/backend/Dockerfile`:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn psycopg2-binary

# Copy application
COPY . .

# Collect static files
RUN python manage.py collectstatic --noinput

EXPOSE 8000

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "config.wsgi:application"]
```

### Dockerfile for Frontend

Create `web/frontend/Dockerfile`:

```dockerfile
FROM node:18 AS builder

WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

### docker-compose.yml

```yaml
version: '3.8'

services:
  db:
    image: postgres:15
    environment:
      POSTGRES_DB: miku_beam_db
      POSTGRES_USER: miku_beam_user
      POSTGRES_PASSWORD: secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  backend:
    build: ./web/backend
    command: gunicorn --bind 0.0.0.0:8000 config.wsgi:application
    volumes:
      - ./web/backend:/app
      - static_volume:/app/staticfiles
    ports:
      - "8000:8000"
    depends_on:
      - db
    environment:
      - DATABASE_URL=postgresql://miku_beam_user:secure_password@db:5432/miku_beam_db

  frontend:
    build: ./web/frontend
    ports:
      - "80:80"
    depends_on:
      - backend

volumes:
  postgres_data:
  static_volume:
```

Deploy:
```bash
docker-compose up -d
```

## Monitoring and Maintenance

### Log Monitoring
```bash
# Gunicorn logs
sudo journalctl -u miku-beam-backend -f

# Nginx logs
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log
```

### Database Backups
```bash
# Backup
pg_dump miku_beam_db > backup_$(date +%Y%m%d).sql

# Restore
psql miku_beam_db < backup_20231201.sql
```

### Updates
```bash
cd /opt/miku-beam-sentinel
git pull
source venv/bin/activate
pip install -r requirements.txt
cd web/backend
python manage.py migrate
python manage.py collectstatic --noinput
sudo systemctl restart miku-beam-backend
```

## Security Checklist

- [ ] Change SECRET_KEY in Django settings
- [ ] Set DEBUG=False
- [ ] Configure ALLOWED_HOSTS properly
- [ ] Enable SSL/TLS with certbot
- [ ] Set strong database passwords
- [ ] Enable firewall (ufw)
- [ ] Regular security updates
- [ ] Configure backup strategy
- [ ] Set up monitoring (optional: Prometheus/Grafana)
- [ ] Review CORS settings

## Troubleshooting

### Backend not starting
```bash
sudo journalctl -u miku-beam-backend --no-pager -n 50
```

### Database connection errors
```bash
sudo -u postgres psql
\l  # List databases
\du # List users
```

### Nginx errors
```bash
sudo nginx -t
sudo tail -f /var/log/nginx/error.log
```

## Support

For issues and questions:
- Check the logs first
- Review Django debug mode (temporarily enable for troubleshooting)
- Verify database connectivity
- Check file permissions
- Ensure all services are running

**Production deployment complete! 🚀**
