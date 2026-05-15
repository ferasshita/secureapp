"""Utility helpers for secure logging and image processing."""
import io
import logging
import uuid
from pathlib import Path

import filetype
from django.conf import settings
from PIL import Image

security_logger = logging.getLogger("security")


def sanitize_log_text(value: str) -> str:
    """SECURITY: strip CR/LF to prevent log injection and forged log lines."""
    return value.replace("\r", " ").replace("\n", " ")


def security_log(event: str, **fields: str) -> None:
    payload = " ".join(f"{k}={sanitize_log_text(str(v))}" for k, v in sorted(fields.items()))
    security_logger.info("%s %s", sanitize_log_text(event), payload)


def save_reencoded_image(uploaded_file) -> str:
    """Validate and re-encode user-uploaded image to safe JPEG output."""
    raw = uploaded_file.read()
    kind = filetype.guess(raw)
    if kind is None or kind.mime not in {"image/jpeg", "image/png"}:
        raise ValueError("Only JPEG and PNG images are allowed.")

    image = Image.open(io.BytesIO(raw))
    # SECURITY: Convert to RGB + re-encode to strip metadata and active payload/polyglot tricks.
    image = image.convert("RGB")
    output = io.BytesIO()
    image.save(output, format="JPEG", quality=90, optimize=True)

    filename = f"{uuid.uuid4().hex}.jpg"
    destination = Path(settings.PROTECTED_MEDIA_ROOT)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / filename).write_bytes(output.getvalue())
    return filename
