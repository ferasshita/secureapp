"""Application URL routes."""
from django.contrib.auth import views as auth_views
from django.urls import path

from .views import (
    PostCreateView,
    PostDeleteView,
    PostDetailView,
    PostListView,
    SecurePasswordChangeDoneView,
    SecurePasswordChangeView,
    admin_login_view,
    image_view,
    login_view,
    logout_view,
    mfa_auth_options,
    mfa_auth_verify,
    mfa_verify_view,
    passkey_delete_view,
    passkey_register_options,
    passkey_register_verify,
    register_view,
    security_log_view,
    settings_view,
)

app_name = "posts"

urlpatterns = [
    path("", PostListView.as_view(), name="home"),
    path("register/", register_view, name="register"),
    path("login/", login_view, name="login"),
    path("logout/", logout_view, name="logout"),
    path("mfa/verify/", mfa_verify_view, name="mfa_verify"),
    path("mfa/options/", mfa_auth_options, name="mfa_auth_options"),
    path("mfa/verify/assertion/", mfa_auth_verify, name="mfa_auth_verify"),
    path("settings/", settings_view, name="settings"),
    path("settings/passkeys/options/", passkey_register_options, name="passkey_register_options"),
    path("settings/passkeys/verify/", passkey_register_verify, name="passkey_register_verify"),
    path("settings/passkeys/<int:key_id>/delete/", passkey_delete_view, name="passkey_delete"),
    path("settings/password/", SecurePasswordChangeView.as_view(), name="password_change"),
    path("settings/password/done/", SecurePasswordChangeDoneView.as_view(), name="password_change_done"),
    path("posts/create/", PostCreateView.as_view(), name="post_create"),
    path("posts/<int:pk>/", PostDetailView.as_view(), name="post_detail"),
    path("posts/<int:pk>/delete/", PostDeleteView.as_view(), name="post_delete"),
    path("media/<str:filename>/", image_view, name="media"),
    path("admin-login/", admin_login_view, name="admin_login_shortcut"),
    path("admin/security-logs/", security_log_view, name="security_logs"),
    path(
        "password-reset/",
        auth_views.PasswordResetView.as_view(template_name="posts/password_reset.html"),
        name="password_reset",
    ),
    path(
        "password-reset/done/",
        auth_views.PasswordResetDoneView.as_view(template_name="posts/password_reset_done.html"),
        name="password_reset_done",
    ),
]
