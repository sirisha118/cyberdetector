#!/usr/bin/env bash
# CyberShield - one-shot setup for Ubuntu 22.04 / 24.04
# Usage: bash scripts/setup_ubuntu.sh
set -euo pipefail

DB_NAME=cybershield
DB_USER=cybershield
DB_PASS="${DB_PASS:-$(openssl rand -hex 12)}"

echo "==> Installing system packages"
sudo apt-get update -y
sudo apt-get install -y python3 python3-venv python3-pip postgresql postgresql-contrib libpq-dev build-essential openssl

echo "==> Creating PostgreSQL role and database"
sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" | grep -q 1 || \
  sudo -u postgres psql -c "CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASS}';"
sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1 || \
  sudo -u postgres createdb -O ${DB_USER} ${DB_NAME}

echo "==> Python virtual environment"
python3 -m venv venv
# shellcheck disable=SC1091
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

if [ ! -f .env ]; then
  echo "==> Writing .env"
  cp .env.example .env
  sed -i "s|^SECRET_KEY=.*|SECRET_KEY=$(openssl rand -hex 32)|" .env
  sed -i "s|^DATABASE_URL=.*|DATABASE_URL=postgresql+psycopg2://${DB_USER}:${DB_PASS}@localhost:5432/${DB_NAME}|" .env
fi

echo "==> Initialising database and ML model"
export FLASK_APP=run.py
flask init-db
flask train-model

echo
echo "Setup complete. Next steps:"
echo "  source venv/bin/activate"
echo "  flask create-admin          # create your admin user"
echo "  flask seed-demo             # (optional) demo data: demo / Demo12345!"
echo "  python run.py               # http://localhost:5000"
echo "  pytest                      # run the test-suite"
