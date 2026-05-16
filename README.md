# 🔒 SecureApp — A Maximum-Security Posting Challenge

![GitHub](https://img.shields.io/github/license/ferasshita/secureapp?style=flat-square)
![Python](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square)
![Django](https://img.shields.io/badge/django-4.2%2B-092e20?style=flat-square)
![Security Headers](https://img.shields.io/badge/security%20headers-A%2B-brightgreen?style=flat-square)
![PRs Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat-square)

A deliberately simple **posting system** built with **every defense-in-depth measure** imaginable.  
This project is both a **secure-by-design reference** and a **challenge lab** — learn, break, fix, and harden.

---

## The Mission

> Build a tiny blog / micro‑posting app that withstands real‑world attacks — from XSS to account takeover.  
> Every feature is implemented with maximum security in mind, leaving no room for common OWASP Top‑10 vulnerabilities.

Whether you’re a developer, penetration tester, or security enthusiast, this repo shows how to do web security **right** — and invites you to find what’s still missing.

---

## Installation

1. Clone the repository and move into it.
2. Create and activate a Python virtual environment.
3. Install dependencies from `requirements.txt`.
4. Set local environment variables.
5. Apply database migrations.
6. Start the development server.

```bash
git clone https://github.com/ferasshita/secureapp.git
cd secureapp

python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

pip install -r requirements.txt

# Local development defaults (disable HTTPS redirect, allow localhost)
export DJANGO_SECURE_SSL_REDIRECT=0
export DJANGO_ALLOWED_HOSTS=127.0.0.1,localhost
export WEBAUTHN_ORIGIN=http://127.0.0.1:8000

python manage.py migrate
python manage.py runserver
```

> 💡 To persist these variables, add them to your shell profile.  
> On Windows, use `set` for the current session or `setx` for permanent storage.

---

## Quick Start

```bash
# Create a superuser (for admin panel)
python manage.py createsuperuser

# (Optional) Load sample posts
python manage.py loaddata sample_posts
```

Visit [http://127.0.0.1:8000](http://127.0.0.1:8000) to see the posting system.

---

## License

MIT © [Feras Shita](https://github.com/ferasshita)  
Use it, break it, learn from it — just keep it secure.

---

## 🌟 Show Your Support

If this project helps you write safer code, give it a ⭐ and share it with your team.  
Together we can make “secure by default” the norm.
