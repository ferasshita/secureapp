"""Data models for secure posts and passkey credentials."""
from django.conf import settings
from django.db import models


class PasskeyCredential(models.Model):
    """Server-side storage for WebAuthn credential material."""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="passkeys")
    name = models.CharField(max_length=128, default="Security Key")
    credential_id = models.TextField(unique=True)
    public_key = models.TextField()
    sign_count = models.PositiveBigIntegerField(default=0)
    transports = models.CharField(max_length=128, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("-created_at",)


class Post(models.Model):
    """Post model with strict owner relationship for object-level authorization."""

    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="posts")
    name = models.CharField(max_length=120)
    description = models.TextField(max_length=2000)
    image_filename = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self) -> str:
        return f"{self.name} by {self.owner}"
