"""Security-focused forms used by the application."""
from django import forms
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.forms import PasswordChangeForm, UserCreationForm
from django.core.exceptions import ValidationError

from .models import Post

User = get_user_model()


class SecureRegistrationForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ("username", "email")


class SecureLoginForm(forms.Form):
    username = forms.CharField(max_length=150)
    password = forms.CharField(widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}))

    def __init__(self, request=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.request = request
        self.user = None

    def clean(self):
        cleaned = super().clean()
        username = cleaned.get("username")
        password = cleaned.get("password")
        if username and password:
            self.user = authenticate(self.request, username=username, password=password)
            if self.user is None:
                raise ValidationError("Invalid credentials.")
        return cleaned


class PostForm(forms.ModelForm):
    image = forms.ImageField(required=True)

    class Meta:
        model = Post
        fields = ("name", "description", "image")

    def clean_name(self):
        value = self.cleaned_data["name"].strip()
        # SECURITY: Reject angle brackets to reduce stored-XSS risk in user generated content.
        if "<" in value or ">" in value:
            raise ValidationError("Name contains invalid characters.")
        return value

    def clean_description(self):
        value = self.cleaned_data["description"].strip()
        # SECURITY: Reject angle brackets to reduce stored-XSS risk in user generated content.
        if "<" in value or ">" in value:
            raise ValidationError("Description contains invalid characters.")
        return value


class EmailUpdateForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ("email",)


class PasskeyDeleteForm(forms.Form):
    password = forms.CharField(widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}))

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user")
        super().__init__(*args, **kwargs)

    def clean_password(self):
        value = self.cleaned_data["password"]
        if not self.user.check_password(value):
            raise ValidationError("Invalid credentials.")
        return value


class SecurePasswordChangeForm(PasswordChangeForm):
    old_password = forms.CharField(
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}),
        strip=False,
    )
    new_password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
        strip=False,
    )
    new_password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
        strip=False,
    )
