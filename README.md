
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Frontend](https://img.shields.io/badge/Frontend-React-blue)](#)
[![Backend](https://img.shields.io/badge/Backend-Flask-green)](#)

**VulnScan Lite** is a lightweight, on-demand web vulnerability scanner for small websites, blogs, and business sites. It performs **passive security checks** like headers, cookies, SSL/TLS, and CMS detection, without aggressive penetration testing.

---

## 🌟 Features

- Simple URL-based scan interface
- HTTP Header & Cookie security checks
- CMS / framework detection
- SSL/TLS certificate validation
- Clear, readable scan reports

---

## ⚡ Tech Stack

- **Frontend**: React.js
- **Backend**: Flask (Python)
- **Libraries**: Requests, BeautifulSoup, Threading
- **Deployment**: GitHub Pages (frontend), Render / Heroku (backend)

---

## 🚀 Quick Start

### Clone Repo

```bash
git clone https://github.com/USERNAME/vulnscan-lite.git
cd vulnscan-lite
````

### Backend Setup

```bash
cd backend
python -m venv venv
# Activate environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

### Frontend Setup

```bash
cd frontend
npm install
npm start
```

Access the app at `http://localhost:3000`.

---

## 🛡️ Disclaimer

* Only scan sites you own or have explicit permission to test.
* This tool is **not a substitute for a professional penetration test**.
* Avoid scanning unauthorized sites.

---

## 📂 Project Structure

```
vulnscan-lite/
├── backend/          # Flask API + scanning modules
├── frontend/         # React UI
├── README.md
└── .gitignore
```

---

## 📄 License

MIT © 2025 Rushabh Borisagar
