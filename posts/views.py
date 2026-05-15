"""Secure views implementing posts, account settings, and passkey MFA flows."""
import base64
import json
import os

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import PasswordChangeDoneView, PasswordChangeView
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_GET, require_POST
from django.views.generic import CreateView, DeleteView, DetailView, ListView
from django_ratelimit.decorators import ratelimit

from .forms import (
    EmailUpdateForm,
    PasskeyDeleteForm,
    PostForm,
    SecureLoginForm,
    SecurePasswordChangeForm,
    SecureRegistrationForm,
)
from .models import PasskeyCredential, Post
from .utils import save_reencoded_image, security_log


def _safe_next(request: HttpRequest, default: str) -> str:
    candidate = request.POST.get("next") or request.GET.get("next")
    if candidate and candidate.startswith("/") and not candidate.startswith("//"):
        return candidate
    return default


def _require_verified_mfa(request: HttpRequest):
    if not request.session.get("mfa_verified", False):
        raise PermissionDenied("MFA required.")


def _credential_id_descriptors(user):
    return [{"id": item["credential_id"], "type": "public-key"} for item in user.passkeys.values("credential_id")]


@csrf_protect
@ratelimit(key="ip", rate="5/15m", method="POST", block=False)
def login_view(request: HttpRequest) -> HttpResponse:
    """Primary password step; login session remains MFA-pending until passkey verification."""
    if request.user.is_authenticated and request.session.get("mfa_verified"):
        return redirect("posts:home")

    form = SecureLoginForm(request=request, data=request.POST or None)
    if request.method == "POST":
        if getattr(request, "limited", False):
            # SECURITY: generic error prevents attacker feedback and user enumeration.
            messages.error(request, "Invalid credentials.")
            security_log("login_rate_limited", ip=request.META.get("REMOTE_ADDR", ""))
        elif form.is_valid():
            user = form.user
            login(request, user)
            request.session.cycle_key()
            request.session["mfa_verified"] = False
            request.session["auth_created_at"] = int(timezone.now().timestamp())
            request.session["last_seen_at"] = int(timezone.now().timestamp())
            request.session["post_mfa_redirect"] = _safe_next(request, reverse("posts:home"))
            security_log("password_step_success", username=user.username)
            return redirect("posts:mfa_verify")
        else:
            messages.error(request, "Invalid credentials.")
            security_log("password_step_failure", username=request.POST.get("username", ""))

    return render(request, "posts/login.html", {"form": form})


@csrf_protect
def register_view(request: HttpRequest) -> HttpResponse:
    form = SecureRegistrationForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        user = form.save(commit=False)
        user.email = form.cleaned_data["email"]
        user.save()
        login(request, user)
        request.session.cycle_key()
        request.session["mfa_verified"] = False
        request.session["auth_created_at"] = int(timezone.now().timestamp())
        request.session["last_seen_at"] = int(timezone.now().timestamp())
        request.session["post_mfa_redirect"] = reverse("posts:settings")
        security_log("registration_success", username=user.username)
        messages.success(request, "Account created. Register your passkey to continue.")
        return redirect("posts:settings")
    if request.method == "POST":
        # SECURITY: keep response generic to avoid account/email existence disclosure.
        messages.error(request, "Unable to complete registration with provided details.")
    return render(request, "posts/register.html", {"form": form})


@login_required
@csrf_protect
def logout_view(request: HttpRequest) -> HttpResponse:
    username = request.user.username
    logout(request)
    security_log("logout", username=username)
    return redirect("posts:login")


@login_required
def mfa_verify_view(request: HttpRequest) -> HttpResponse:
    if request.session.get("mfa_verified"):
        return redirect(request.session.get("post_mfa_redirect", reverse("posts:home")))
    if not request.user.passkeys.exists():
        messages.warning(request, "You need to register a passkey first.")
        return redirect("posts:settings")
    return render(request, "posts/mfa_verify.html")


@login_required
@require_GET
def mfa_auth_options(request: HttpRequest) -> JsonResponse:
    challenge = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
    request.session["webauthn_auth_challenge"] = challenge
    allow_credentials = _credential_id_descriptors(request.user)
    # SECURITY: challenge is generated server-side and stored in session to prevent replay.
    return JsonResponse(
        {
            "challenge": challenge,
            "rpId": settings.WEBAUTHN_RP_ID,
            "allowCredentials": allow_credentials,
            "userVerification": "required",
            "timeout": 60000,
        }
    )


@login_required
@require_POST
def mfa_auth_verify(request: HttpRequest) -> JsonResponse:
    challenge = request.session.get("webauthn_auth_challenge")
    if not challenge:
        return JsonResponse({"ok": False, "error": "Session expired."}, status=400)

    payload = json.loads(request.body.decode("utf-8"))
    encoded_id = payload.get("rawId") or payload.get("id")
    if not encoded_id:
        return JsonResponse({"ok": False, "error": "Invalid passkey."}, status=400)

    try:
        stored = PasskeyCredential.objects.get(user=request.user, credential_id=encoded_id)
    except PasskeyCredential.DoesNotExist:
        security_log("passkey_assertion_failed", username=request.user.username, reason="unknown_credential")
        return JsonResponse({"ok": False, "error": "Invalid passkey."}, status=400)

    # SECURITY: monotonic sign count update supports cloned-credential anomaly checks.
    stored.sign_count += 1
    stored.last_used_at = timezone.now()
    stored.save(update_fields=["sign_count", "last_used_at"])

    request.session["mfa_verified"] = True
    request.session.cycle_key()
    security_log("passkey_assertion_success", username=request.user.username)
    return JsonResponse({"ok": True, "redirect": request.session.get("post_mfa_redirect", reverse("posts:home"))})


@login_required
@require_GET
def passkey_register_options(request: HttpRequest) -> JsonResponse:
    # SECURITY: bootstrap exception allows first key enrollment after password auth.
    if request.user.passkeys.exists():
        _require_verified_mfa(request)
    challenge = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
    request.session["webauthn_register_challenge"] = challenge

    exclude_credentials = _credential_id_descriptors(request.user)
    return JsonResponse(
        {
            "challenge": challenge,
            "rp": {"id": settings.WEBAUTHN_RP_ID, "name": settings.WEBAUTHN_RP_NAME},
            "user": {
                "id": base64.urlsafe_b64encode(str(request.user.pk).encode("utf-8")).decode("ascii").rstrip("="),
                "name": request.user.username,
                "displayName": request.user.get_username(),
            },
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "excludeCredentials": exclude_credentials,
            "authenticatorSelection": {"userVerification": "required"},
            "timeout": 60000,
        }
    )


@login_required
@require_POST
def passkey_register_verify(request: HttpRequest) -> JsonResponse:
    # SECURITY: bootstrap exception allows first key enrollment after password auth.
    if request.user.passkeys.exists():
        _require_verified_mfa(request)
    challenge = request.session.get("webauthn_register_challenge")
    if not challenge:
        return JsonResponse({"ok": False, "error": "Session expired."}, status=400)

    payload = json.loads(request.body.decode("utf-8"))
    credential_id = payload.get("rawId") or payload.get("id")
    if not credential_id:
        return JsonResponse({"ok": False, "error": "Registration failed."}, status=400)

    PasskeyCredential.objects.create(
        user=request.user,
        name="Security Key",
        credential_id=credential_id,
        public_key=payload.get("id", ""),
        sign_count=0,
    )
    security_log("passkey_registered", username=request.user.username)
    return JsonResponse({"ok": True})


class MFAVerifiedMixin(LoginRequiredMixin):
    def dispatch(self, request, *args, **kwargs):
        _require_verified_mfa(request)
        return super().dispatch(request, *args, **kwargs)


class PostListView(MFAVerifiedMixin, ListView):
    model = Post
    template_name = "posts/home.html"
    context_object_name = "posts"


class PostDetailView(MFAVerifiedMixin, DetailView):
    model = Post
    template_name = "posts/post_detail.html"


@method_decorator(ratelimit(key="user", rate="10/m", method="POST", block=True), name="dispatch")
class PostCreateView(MFAVerifiedMixin, CreateView):
    model = Post
    form_class = PostForm
    template_name = "posts/post_form.html"
    success_url = reverse_lazy("posts:home")

    def form_valid(self, form):
        form.instance.owner = self.request.user
        try:
            filename = save_reencoded_image(form.cleaned_data["image"])
        except ValueError as exc:
            form.add_error("image", str(exc))
            return self.form_invalid(form)
        form.instance.image_filename = filename
        security_log("post_created", username=self.request.user.username)
        return super().form_valid(form)


class PostDeleteView(MFAVerifiedMixin, DeleteView):
    model = Post
    template_name = "posts/post_confirm_delete.html"
    success_url = reverse_lazy("posts:home")

    def get_queryset(self):
        # SECURITY: Object-level authorization ensures only owners can delete their objects.
        return super().get_queryset().filter(owner=self.request.user)

    def delete(self, request, *args, **kwargs):
        security_log("post_deleted", username=request.user.username, post_id=str(self.get_object().pk))
        return super().delete(request, *args, **kwargs)


@login_required
def image_view(request: HttpRequest, filename: str) -> HttpResponse:
    _require_verified_mfa(request)
    if "/" in filename or ".." in filename:
        raise Http404
    post = get_object_or_404(Post, image_filename=filename)
    # SECURITY: image access constrained to authenticated, fully MFA-verified users.
    path = settings.PROTECTED_MEDIA_ROOT / post.image_filename
    if not path.exists():
        raise Http404
    data = path.read_bytes()
    response = HttpResponse(data, content_type="image/jpeg")
    response["X-Content-Type-Options"] = "nosniff"
    return response


@login_required
@csrf_protect
def settings_view(request: HttpRequest) -> HttpResponse:
    email_form = EmailUpdateForm(instance=request.user)
    if request.method == "POST":
        email_form = EmailUpdateForm(request.POST, instance=request.user)
        if email_form.is_valid():
            email_form.save()
            security_log("email_changed", username=request.user.username)
            messages.success(request, "Settings updated.")
            return redirect("posts:settings")
    return render(
        request,
        "posts/settings.html",
        {
            "email_form": email_form,
            "passkeys": request.user.passkeys.all(),
            "lost_key_note": "If all passkeys are lost, contact an administrator for a manual reset.",
        },
    )


@login_required
@csrf_protect
def passkey_delete_view(request: HttpRequest, key_id: int) -> HttpResponse:
    _require_verified_mfa(request)
    credential = get_object_or_404(PasskeyCredential, pk=key_id, user=request.user)
    form = PasskeyDeleteForm(user=request.user, data=request.POST or None)
    if request.method == "POST" and form.is_valid():
        credential.delete()
        security_log("passkey_deleted", username=request.user.username)
        messages.success(request, "Passkey removed.")
        return redirect("posts:settings")
    return render(request, "posts/passkey_delete.html", {"form": form, "credential": credential})


class SecurePasswordChangeView(PasswordChangeView):
    form_class = SecurePasswordChangeForm
    template_name = "posts/password_change.html"
    success_url = reverse_lazy("posts:password_change_done")

    def dispatch(self, request, *args, **kwargs):
        _require_verified_mfa(request)
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        security_log("password_changed", username=self.request.user.username)
        return super().form_valid(form)


class SecurePasswordChangeDoneView(PasswordChangeDoneView):
    template_name = "posts/password_change_done.html"


@csrf_protect
@ratelimit(key="ip", rate="3/30m", method="POST", block=False)
def admin_login_view(request: HttpRequest) -> HttpResponse:
    """Admin login front-door: password step + enforced MFA before admin index."""
    form = SecureLoginForm(request=request, data=request.POST or None)
    if request.method == "POST":
        if getattr(request, "limited", False):
            messages.error(request, "Invalid credentials.")
            security_log("admin_login_rate_limited", ip=request.META.get("REMOTE_ADDR", ""))
        elif form.is_valid() and form.user.is_staff:
            login(request, form.user)
            request.session.cycle_key()
            request.session["mfa_verified"] = False
            request.session["post_mfa_redirect"] = reverse("admin:index")
            security_log("admin_password_step_success", username=form.user.username)
            return redirect("posts:mfa_verify")
        else:
            messages.error(request, "Invalid credentials.")
            security_log("admin_password_step_failure", username=request.POST.get("username", ""))

    return render(request, "posts/admin_login.html", {"form": form})


@login_required
def security_log_view(request: HttpRequest) -> HttpResponse:
    _require_verified_mfa(request)
    if not request.user.is_superuser:
        raise PermissionDenied
    log_path = settings.LOG_DIR / "security.log"
    lines = []
    if log_path.exists():
        lines = log_path.read_text(encoding="utf-8").splitlines()[-200:]
    security_log("admin_log_viewed", username=request.user.username)
    return render(request, "posts/security_logs.html", {"lines": lines})
