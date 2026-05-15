from django.contrib import admin
from django.urls import include, path
from django.conf import settings

from posts import views as post_views

urlpatterns = [
    path("", include("posts.urls")),
    # SECURITY: Override admin login endpoint to apply explicit MFA pre-check and strict rate-limit.
    path(f"{settings.ADMIN_URL_PATH}login/", post_views.admin_login_view, name="admin-login"),
    # SECURITY: Obscured admin URL reduces automated probing while still relying on strong auth.
    path(settings.ADMIN_URL_PATH, admin.site.urls),
]
