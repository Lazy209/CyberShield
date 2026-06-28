# CyberShield — AI-Powered Cybersecurity Threat Detection Platform

**Cybersecurity Internship Project** · Full-stack web application

---

## Features (12 Modules)

| # | Module | Description |
|---|--------|-------------|
| 1 | **JWT Login** | Secure authentication with JSON Web Tokens |
| 2 | **Vulnerability Scanner** | HTTP security headers, SSL, server misconfigurations |
| 3 | **Password Analyzer** | Strength scoring, entropy, common password detection |
| 4 | **Phishing URL Detector** | Heuristic analysis for suspicious URLs |
| 5 | **File Hash Checker** | MD5/SHA256 hashing + malware database lookup |
| 6 | **Threat Intelligence** | Charts and metrics from scan history |
| 7 | **Security News** | Live RSS feeds from cybersecurity sources |
| 8 | **Log Analyzer** | Detect failed logins, SQLi, XSS in log files |
| 9 | **PDF Reports** | Download professional scan reports |
| 10 | **Admin Dashboard** | User management and system stats |
| 11 | **User History** | Personal scan history with PDF export |
| 12 | **AI Assistant** | Cybersecurity Q&A (OpenAI API + offline fallback) |

---

## Quick Start

```powershell
cd CyberShield
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python app.py
```

Or double-click **`run.bat`**.

Open: **http://127.0.0.1:5000**

### Default Admin Login

| Field | Value |
|-------|-------|
| Username | `admin` |
| Password | `admin123` |

---

## Tech Stack

- **Backend:** Python 3, Flask, Flask-JWT-Extended
- **Database:** SQLite
- **Frontend:** HTML5, CSS3, JavaScript, Chart.js
- **PDF:** ReportLab
- **News:** RSS (feedparser)
- **AI:** OpenAI-compatible API (optional)

---

## AI Assistant Setup (Optional)

Add to `.env`:

```env
OPENAI_API_KEY=your-api-key-here
```

Without an API key, the assistant uses built-in offline knowledge base.

---

## Project Structure

```
CyberShield/
├── app.py                 # Main Flask application
├── config.py              # Configuration
├── database.py            # SQLite layer
├── project_info.py        # Student details (edit before submission)
├── services/              # Security analysis modules
│   ├── password_analyzer.py
│   ├── url_detector.py
│   ├── vuln_scanner.py
│   ├── hash_checker.py
│   ├── log_analyzer.py
│   ├── news_fetcher.py
│   ├── ai_assistant.py
│   └── pdf_report.py
├── templates/             # HTML pages
├── static/                # CSS & JavaScript
└── data/                  # SQLite database
```

---

## For College Submission

1. Edit `project_info.py` with your name, roll number, college
2. Run the website and take screenshots of all modules
3. Export this README + screenshots as your project report
4. Zip the folder (exclude `.venv`) and submit

---

## Ethics

This platform is for **educational and authorized security testing only**. Use vulnerability scanning only on sites you own or have permission to test.
