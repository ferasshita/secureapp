"""Security-hardened Django settings for the secure posting system."""
import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY: Secret key comes from env so production secrets are never committed.
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "unsafe-dev-key-change-me")

# SECURITY: Debug is off by default to avoid verbose error pages and info leaks.
DEBUG = False

ALLOWED_HOSTS = [h.strip() for h in os.environ.get("DJANGO_ALLOWED_HOSTS", "127.0.0.1,localhost").split(",") if h.strip()]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "axes",  # SECURITY: Login abuse detection and account lockout support.
    "csp",  # SECURITY: Content Security Policy headers for XSS mitigation.
    "posts",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "axes.middleware.AxesMiddleware",  # SECURITY: Tracks and blocks repeated auth failures.
    "posts.middleware.SessionTimeoutMiddleware",  # SECURITY: Enforces idle + absolute session timeouts.
    "posts.middleware.MFARequiredMiddleware",  # SECURITY: Blocks app access until passkey MFA succeeds.
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "csp.middleware.CSPMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        # SECURITY: Strong password baseline (>=12 chars) for credential resistance.
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 12},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# SECURITY: Argon2id is preferred for stronger password hashing against brute-force.
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

# SECURITY: User uploads are private and served only through an authorization-aware view.
PROTECTED_MEDIA_ROOT = BASE_DIR / "media_protected"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# SECURITY: HTTPS/session cookie hardening.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = os.environ.get("DJANGO_SECURE_SSL_REDIRECT", "0" if "test" in sys.argv else "1") == "1"
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"
CSRF_USE_SESSIONS = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
SECURE_HSTS_SECONDS = 63072000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# SECURITY: Session lifetime controls reduce risk from stolen session cookies.
SESSION_SAVE_EVERY_REQUEST = True
SESSION_COOKIE_AGE = 60 * 30
POSTS_IDLE_TIMEOUT_SECONDS = 60 * 30
POSTS_ABSOLUTE_TIMEOUT_SECONDS = 60 * 60 * 2

LOGIN_URL = "posts:login"
LOGIN_REDIRECT_URL = "posts:home"
LOGOUT_REDIRECT_URL = "posts:login"

# SECURITY: Admin URL is non-default to reduce automated attack noise.
ADMIN_URL_PATH = os.environ.get("DJANGO_ADMIN_URL", "secure-admin/").lstrip("/")

# SECURITY: Apply explicit CSP policy aligned with OWASP XSS mitigation guidance.
CSP_DEFAULT_SRC = ("'self'",)
CSP_IMG_SRC = ("'self'", "data:")
CSP_SCRIPT_SRC = ("'self'",)
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")
CSP_OBJECT_SRC = ("'none'",)
CSP_BASE_URI = ("'self'",)
CSP_FORM_ACTION = ("'self'",)
CSP_UPGRADE_INSECURE_REQUESTS = True

# SECURITY: Axes lockout for authentication failures.
AXES_ENABLED = True
AXES_FAILURE_LIMIT = 5
AXES_COOLOFF_TIME = 0.25  # 15 minutes.
AXES_LOCKOUT_PARAMETERS = ["username", "ip_address"]
AXES_RESET_ON_SUCCESS = True

AUTHENTICATION_BACKENDS = [
    "axes.backends.AxesStandaloneBackend",
    "django.contrib.auth.backends.ModelBackend",
]

# SECURITY: Relying party settings for passkeys/WebAuthn ceremony validation.
WEBAUTHN_RP_ID = os.environ.get("WEBAUTHN_RP_ID", "localhost")
WEBAUTHN_RP_NAME = os.environ.get("WEBAUTHN_RP_NAME", "Secure College App")
WEBAUTHN_ORIGIN = os.environ.get("WEBAUTHN_ORIGIN", "https://localhost")

# SECURITY: Dedicated audit log file; keep sensitive data out of log payloads.
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"security": {"format": "%(asctime)s %(levelname)s %(name)s %(message)s"}},
    "handlers": {
        "security_file": {
            "class": "logging.FileHandler",
            "filename": str(LOG_DIR / "security.log"),
            "formatter": "security",
        }
    },
    "loggers": {"security": {"handlers": ["security_file"], "level": "INFO", "propagate": False}},
}
