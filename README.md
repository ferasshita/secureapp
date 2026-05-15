# secureapp

## Installation

1. Clone the repository and move into it.
2. Create and activate a virtual environment.
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

# local dev defaults
export DJANGO_SECURE_SSL_REDIRECT=0
export DJANGO_ALLOWED_HOSTS=127.0.0.1,localhost
export WEBAUTHN_ORIGIN=http://127.0.0.1:8000

python manage.py migrate
python manage.py runserver
```

The `export` values above apply to the current shell session; to persist them, add them to your shell profile (Windows: use `set` for session-only values or `setx VAR_NAME value` for persistent values).
