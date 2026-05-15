from io import BytesIO

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse
from PIL import Image

from .models import PasskeyCredential, Post

User = get_user_model()


class AuthFlowTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", email="a@example.com", password="ComplexPass123!")

    def test_login_requires_mfa_redirect(self):
        response = self.client.post(reverse("posts:login"), {"username": "alice", "password": "ComplexPass123!"})
        self.assertRedirects(response, reverse("posts:mfa_verify"), fetch_redirect_response=False)
        self.assertFalse(self.client.session.get("mfa_verified", False))

    def test_authenticated_user_without_passkey_redirected_to_settings(self):
        self.client.force_login(self.user)
        session = self.client.session
        session["mfa_verified"] = True
        session.save()
        response = self.client.get(reverse("posts:home"))
        self.assertRedirects(response, reverse("posts:settings"))


class PostSecurityTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(username="owner", password="ComplexPass123!")
        self.other = User.objects.create_user(username="other", password="ComplexPass123!")
        PasskeyCredential.objects.create(user=self.other, credential_id="cred-other", public_key="pk")
        self.post = Post.objects.create(owner=self.owner, name="n", description="d", image_filename="x.jpg")

    def test_owner_only_delete(self):
        self.client.force_login(self.other)
        session = self.client.session
        session["mfa_verified"] = True
        session.save()
        response = self.client.post(reverse("posts:post_delete", args=[self.post.pk]))
        self.assertEqual(response.status_code, 404)


class InputValidationTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="poster", password="ComplexPass123!")
        PasskeyCredential.objects.create(user=self.user, credential_id="cred-user", public_key="pk")

    def _jpeg(self):
        file_obj = BytesIO()
        Image.new("RGB", (1, 1), "white").save(file_obj, format="JPEG")
        return SimpleUploadedFile("safe.jpg", file_obj.getvalue(), content_type="image/jpeg")

    def test_reject_angle_brackets(self):
        self.client.force_login(self.user)
        session = self.client.session
        session["mfa_verified"] = True
        session.save()
        response = self.client.post(
            reverse("posts:post_create"),
            {"name": "<bad>", "description": "ok", "image": self._jpeg()},
        )
        self.assertContains(response, "invalid characters", status_code=200)
