"""Custom middleware for MFA gating and session timeout enforcement."""
import time

from django.conf import settings
from django.contrib import messages
from django.shortcuts import redirect
from django.urls import resolve


class SessionTimeoutMiddleware:
    """SECURITY: Enforce both idle timeout and absolute timeout for active sessions."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            now = int(time.time())
            created = request.session.get("auth_created_at", now)
            last_seen = request.session.get("last_seen_at", now)
            request.session.setdefault("auth_created_at", now)
            request.session["last_seen_at"] = now

            if now - last_seen > settings.POSTS_IDLE_TIMEOUT_SECONDS:
                request.session.flush()
                messages.error(request, "Your session expired. Please sign in again.")
                return redirect("posts:login")

            if now - created > settings.POSTS_ABSOLUTE_TIMEOUT_SECONDS:
                request.session.flush()
                messages.error(request, "Your session timed out. Please sign in again.")
                return redirect("posts:login")

        return self.get_response(request)


class MFARequiredMiddleware:
    """SECURITY: Block app/admin access until a logged-in user completes passkey MFA."""

    EXEMPT_NAMES = {
        "posts:login",
        "posts:register",
        "posts:logout",
        "posts:mfa_verify",
        "posts:mfa_auth_options",
        "posts:mfa_auth_verify",
        "posts:passkey_register_options",
        "posts:passkey_register_verify",
        "posts:settings",
        "posts:password_change",
        "posts:password_change_done",
        "posts:passkey_delete",
        "posts:password_reset",
        "posts:password_reset_done",
        "admin-login",
        "admin:login",
    }

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            match = resolve(request.path_info)
            current_name = f"{match.namespace}:{match.url_name}" if match.namespace else match.url_name
            has_keys = request.user.passkeys.exists()

            if not has_keys and current_name not in {
                "posts:settings",
                "posts:passkey_register_options",
                "posts:passkey_register_verify",
                "posts:logout",
            }:
                messages.warning(request, "You must register a passkey before using the app.")
                return redirect("posts:settings")

            if not request.session.get("mfa_verified", True) and current_name not in self.EXEMPT_NAMES:
                return redirect("posts:mfa_verify")

        return self.get_response(request)
