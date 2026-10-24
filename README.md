# 🛡️ CyberShield — AI-Powered Email Threat Detection & Automatic Blocking

CyberShield is a web platform that scans incoming e-mail for **phishing, spam, malicious links, dangerous
attachments and business-email-compromise**, scores each message (0–100), and **automatically allows,
quarantines or blocks** it according to configurable security rules. A dashboard shows threats, history,
alerts and statistics.

**Stack:** Python · Flask · Flask-Login · Flask-SQLAlchemy · PostgreSQL · HTML5/CSS3/JS · Bootstrap 5 ·
scikit-learn · pandas · `email` parsing · IMAP/SMTP · DNS/URL reputation APIs · APScheduler · REST API · pytest · Ubuntu

---

## How detection works

Every message goes through a pipeline (`app/services/detector.py`); each stage adds *explainable* risk points:

| Stage | Module | Examples |
|---|---|---|
| Sender lists | `detector.py` | block-list match ⇒ instant block; allow-list skips scoring (never for malware) |
| Heuristics | `heuristics.py` | urgency/credential/spam/BEC wording, display-name spoofing, look-alike domains (`paypa1.com`), Reply-To mismatch, SPF/DKIM/DMARC failures, password forms |
| ML classifier | `ml/classifier.py` | TF-IDF + Logistic Regression → ham / spam / phishing probabilities |
| URL reputation | `url_reputation.py` | raw-IP links, punycode, shorteners, bad TLDs, anchor-text ≠ target, brand in sub-domain, DNS resolution, Spamhaus DBL, Google Safe Browsing, VirusTotal |
| Attachments | `attachments.py` | executables/scripts, macro Office files, double extensions, disguised EXE/ELF, password-protected & malicious archives, EICAR/known hashes |
| Custom rules | UI → *Rules* | your own keyword/regex rules with +/- points |

Score → level (`safe <20 · low <40 · medium <70 · high <85 · critical`) → action using your thresholds
(default: **quarantine ≥ 40, block ≥ 70**). Blocked mail can auto-add the sender to the block list.
Confirmed malware is always blocked. For IMAP mailboxes threats are physically moved to a
`CyberShield-Quarantine` folder and can be released back to the inbox.

## Features
* Registration/login (Flask-Login, hashed passwords, CSRF protection, per-user data isolation; first user = admin)
* Dashboard (pandas stats + Chart.js), scan history with filters, e-mail detail with "why this verdict?"
* Quarantine manager (release / false-positive allow-listing / delete)
* Block & allow lists (address or whole domain), auto-block of repeat offenders
* Security alerts (in-app + optional SMTP e-mail)
* Mailbox connections via **IMAP** (passwords stored Fernet-encrypted), background polling with **APScheduler**
* Manual scan (paste / upload `.eml`) and **REST API** with per-user API key
* Retention job purges old history; rotating log file in `logs/`

## Quick start (Ubuntu 22.04/24.04)

```bash
unzip cybershield.zip && cd cybershield
bash scripts/setup_ubuntu.sh        # installs PostgreSQL + venv, creates DB, .env, trains model
source venv/bin/activate
export FLASK_APP=run.py
flask create-admin                  # or just register in the browser (first user = admin)
flask seed-demo                     # optional demo data  (demo / Demo12345!)
python run.py                       # → http://localhost:5000
```

Manual setup: create a PostgreSQL DB, `cp .env.example .env`, set `DATABASE_URL` and `SECRET_KEY`,
`pip install -r requirements.txt`, `flask init-db`, `flask train-model`.
Quick try without PostgreSQL: `DATABASE_URL=sqlite:///cybershield.sqlite3 python run.py`.
`docker compose up -d db` starts a ready-made PostgreSQL if you prefer Docker.

## Connecting a mailbox
*Mailboxes → Add mailbox.* Gmail: `imap.gmail.com:993`, SMTP `smtp.gmail.com:587`, use an **App Password**.
Press **Test**, then **Scan now**; afterwards the scheduler polls every *N* minutes. New mail is scanned
read-only (`BODY.PEEK`), threats are moved to the quarantine folder. First poll reads the latest 50 messages.

## REST API
Header `X-API-Key: <key from Profile page>`

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/health` | liveness |
| POST | `/api/v1/scan` | scan raw RFC822 (`Content-Type: message/rfc822`) **or** JSON `{from, to, subject, body}` |
| GET | `/api/v1/scans?action=&level=&verdict=&page=` | scan history |
| GET | `/api/v1/scans/<id>` | full detail incl. reasons, URLs, attachments |
| GET | `/api/v1/stats?days=14` | dashboard statistics |
| GET/POST | `/api/v1/senders` | list / add `{pattern, list_type: block|allow, reason}` |
| DELETE | `/api/v1/senders/<id>` | remove entry |
| GET | `/api/v1/alerts` | latest alerts |

```bash
curl -X POST http://localhost:5000/api/v1/scan -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"from":"PayPal <a@paypa1.com>","subject":"Verify your account immediately","body":"Click http://198.51.100.9/login"}'
```

## Configuration (`.env`)
See `.env.example`. Optional reputation providers: `GOOGLE_SAFE_BROWSING_KEY`, `VIRUSTOTAL_API_KEY`;
`URL_DNS_CHECK`, `DNSBL_ENABLED` toggle network lookups. Alert e-mail fallback: `ALERT_SMTP_*`.
Thresholds, toggles and custom rules are edited per user under **Rules**.

## Improving the ML model
The bundled model trains on a **small synthetic demo dataset** (`scripts/generate_sample_data.py`) so the
project works offline. For real accuracy retrain on a real corpus (SpamAssassin, Enron, Nazario phishing…):
```bash
flask train-model --csv my_emails.csv     # columns: text,label  (ham | spam | phishing)
```

## Tests
```bash
pytest -q        # parser, detector, heuristics, attachments, web UI, REST API, IMAP polling (mocked)
```

## Production notes
* `FLASK_CONFIG=production`, strong `SECRET_KEY` (also used to derive the mailbox-password encryption key —
  changing it requires re-entering mailbox passwords), HTTPS + `SESSION_COOKIE_SECURE=true`.
* `deploy/cybershield.service` (gunicorn, **single worker group** so only one scheduler runs) and `deploy/nginx.conf`.
* Use Alembic/Flask-Migrate if you later change the schema; `flask init-db` only creates missing tables.

## Project layout
```
app/            Flask package  (models, auth/, main/, api/, services/, ml/, templates/, static/)
tests/          pytest suite        samples/   .eml test messages (phishing, spam, malware EICAR, legit)
scripts/        setup_ubuntu.sh, sample-data generators     deploy/   systemd + nginx
config.py run.py wsgi.py requirements.txt .env.example docker-compose.yml
```
The EICAR file in `samples/malware.eml` is the harmless industry-standard antivirus test string.
