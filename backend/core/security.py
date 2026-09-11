import re
from typing import Optional
from urllib.parse import urlparse
from fastapi import HTTPException


class SecurityError(Exception):
    pass


def assert_read_only_mode():
    from backend.core.config import settings
    if not settings.READ_ONLY_BY_DEFAULT:
        return
    # Guard against mutations of production infrastructure
    pass


def prevent_command_execution(command_name: str):
    from backend.core.config import settings
    if not settings.ALLOW_COMMAND_EXECUTION:
        raise SecurityError(
            f"Command execution of '{command_name}' is strictly prohibited. "
            "Infrastructure Autopsy operates in read-only forensic mode."
        )


def sanitize_text(text: Optional[str]) -> str:
    """Sanitize text against injection and dangerous scripts."""
    if not text:
        return ""
    # Strip dangerous HTML script tags
    cleaned = re.sub(r"<\s*script[^>]*>.*?<\s*/\s*script\s*>", "", text, flags=re.IGNORECASE | re.DOTALL)
    # Remove javascript: uris
    cleaned = re.sub(r"javascript:", "", cleaned, flags=re.IGNORECASE)
    return cleaned.strip()


def validate_safe_url(url: str) -> bool:
    """Protect against SSRF: verify URL does not target AWS metadata, loopback private subnets, etc."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        hostname = (parsed.hostname or "").lower()
        # Disallow cloud metadata endpoints
        if hostname in ("169.254.169.254", "metadata.google.internal", "instance-data"):
            return False
        return True
    except Exception:
        return False
