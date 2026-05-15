from django.contrib import admin

from .models import PasskeyCredential, Post


@admin.register(Post)
class PostAdmin(admin.ModelAdmin):
    list_display = ("id", "owner", "name", "created_at")
    search_fields = ("name", "owner__username")


@admin.register(PasskeyCredential)
class PasskeyCredentialAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "name", "created_at", "last_used_at")
    search_fields = ("user__username", "name")
